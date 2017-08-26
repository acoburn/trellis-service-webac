/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.trellisldp.webac;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.empty;
import static org.slf4j.LoggerFactory.getLogger;
import static org.trellisldp.spi.RDFUtils.getInstance;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.Triple;
import org.slf4j.Logger;

import org.trellisldp.api.Resource;
import org.trellisldp.spi.AccessControlService;
import org.trellisldp.spi.AgentService;
import org.trellisldp.spi.Authorization;
import org.trellisldp.spi.ResourceService;
import org.trellisldp.spi.RuntimeRepositoryException;
import org.trellisldp.spi.Session;
import org.trellisldp.vocabulary.ACL;
import org.trellisldp.vocabulary.RDF;
import org.trellisldp.vocabulary.Trellis;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final Logger LOGGER = getLogger(WebACService.class);

    private final ResourceService resourceService;

    private final AgentService agentService;

    /**
     * Create a WebAC-base authorization service
     * @param resourceService the resource service
     * @param agentService the agent service
     */
    public WebACService(final ResourceService resourceService, final AgentService agentService) {
        requireNonNull(resourceService, "A non-null ResourceService must be provided!");
        requireNonNull(agentService, "A non-null AgentService must be provided!");
        this.resourceService = resourceService;
        this.agentService = agentService;
    }

    @Override
    public Boolean anyMatch(final Session session, final IRI identifier, final Predicate<IRI> predicate) {
        requireNonNull(session, "A non-null session must be provided!");
        requireNonNull(predicate, "A non-null predicate must be provided!");

        if (Trellis.RepositoryAdministrator.equals(session.getAgent()) || agentService.isAdmin(session.getAgent())) {
            return true;
        }

        return getNearestResource(identifier).map(resource -> getAllAuthorizationsFor(resource, true)
                .filter(delegateFilter(session).negate())
                .filter(agentGroupFilter(session, getGroups(session.getAgent()))))
            .orElse(empty())
            .peek(auth -> LOGGER.debug("Applying Authorization {} to {}", auth.getIdentifier(), identifier))
            .anyMatch(auth -> auth.getMode().stream().anyMatch(predicate));
    }

    private Optional<Resource> getNearestResource(final IRI identifier) {
        final Optional<Resource> res = resourceService.get(identifier);
        if (res.isPresent()) {
            return res;
        }
        return resourceService.getContainer(identifier).flatMap(this::getNearestResource);
    }

    private Predicate<Authorization> agentGroupFilter(final Session session, final List<IRI> agentGroups) {
        return auth -> auth.getAgent().contains(session.getAgent()) ||
            agentGroups.stream().anyMatch(auth.getAgentGroup()::contains);
    }

    private Predicate<Authorization> delegateFilter(final Session session) {
        return auth -> session.getDelegatedBy().filter(delegate -> !auth.getAgent().contains(delegate)).isPresent();
    }

    private List<IRI> getGroups(final IRI agent) {
        return agentService.getGroups(agent).collect(toList());
    }

    private Predicate<Authorization> getInheritedAuth(final IRI identifier) {
        return auth -> auth.getDefault().contains(identifier);
    }

    private Predicate<Authorization> getAccessToAuth(final IRI identifier) {
        return auth -> auth.getAccessTo().contains(identifier);
    }

    private List<Authorization> getAuthorizationFromGraph(final Graph graph) {
        return graph.stream(null, RDF.type, ACL.Authorization).map(Triple::getSubject).distinct().map(subject -> {
                try (final Graph authGraph = getInstance().createGraph()) {
                    graph.stream(subject, null, null).forEach(authGraph::add);
                    return Authorization.from(subject, authGraph);
                } catch (final Exception ex) {
                    throw new RuntimeRepositoryException("Error Processing graph", ex);
                }
            }).collect(toList());
    }

    private Stream<Authorization> getAllAuthorizationsFor(final Resource resource, final Boolean top) {
        final Optional<IRI> parent = resourceService.getContainer(resource.getIdentifier());

        try (final Graph graph = getInstance().createGraph()) {
            resource.stream(Trellis.PreferAccessControl).forEach(graph::add);

            if (graph.size() == 0) {
                // Nothing here, check the parent
                return parent.flatMap(resourceService::get).map(res -> getAllAuthorizationsFor(res, false))
                    .orElse(Stream.empty());
            }

            final List<Authorization> authorizations = getAuthorizationFromGraph(graph);

            if (!top && authorizations.stream().anyMatch(getInheritedAuth(resource.getIdentifier()))) {
                return authorizations.stream().filter(getInheritedAuth(resource.getIdentifier()));
            }
            return authorizations.stream().filter(getAccessToAuth(resource.getIdentifier()));
        } catch (final Exception ex) {
            throw new RuntimeRepositoryException(ex);
        }
    }
}
