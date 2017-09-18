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
import static org.trellisldp.spi.RDFUtils.cleanIdentifier;
import static org.trellisldp.spi.RDFUtils.getInstance;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDFTerm;
import org.apache.commons.rdf.api.Triple;
import org.slf4j.Logger;

import org.trellisldp.api.Resource;
import org.trellisldp.spi.AccessControlService;
import org.trellisldp.spi.Authorization;
import org.trellisldp.spi.ResourceService;
import org.trellisldp.spi.RuntimeRepositoryException;
import org.trellisldp.spi.Session;
import org.trellisldp.vocabulary.ACL;
import org.trellisldp.vocabulary.FOAF;
import org.trellisldp.vocabulary.RDF;
import org.trellisldp.vocabulary.Trellis;
import org.trellisldp.vocabulary.VCARD;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final Logger LOGGER = getLogger(WebACService.class);

    private final ResourceService resourceService;

    /**
     * Create a WebAC-base authorization service
     * @param resourceService the resource service
     */
    public WebACService(final ResourceService resourceService) {
        requireNonNull(resourceService, "A non-null ResourceService must be provided!");
        this.resourceService = resourceService;
    }

    @Override
    public Boolean anyMatch(final Session session, final IRI identifier, final Predicate<IRI> predicate) {
        requireNonNull(session, "A non-null session must be provided!");
        requireNonNull(predicate, "A non-null predicate must be provided!");

        if (Trellis.RepositoryAdministrator.equals(session.getAgent())) {
            return true;
        }

        return getNearestResource(identifier).map(resource -> getAllAuthorizationsFor(resource, true)
                .filter(delegateFilter(session).negate())
                .filter(agentFilter(session)))
            .orElseGet(Stream::empty)
            .peek(auth -> LOGGER.debug("Applying Authorization {} to {}", auth.getIdentifier(), identifier))
            .anyMatch(auth -> auth.getMode().stream().anyMatch(predicate));
    }

    private Optional<Resource> getNearestResource(final IRI identifier) {
        final Optional<Resource> res = resourceService.get(identifier);
        // TODO -- JDK9 refactor with Optional::or
        if (res.isPresent()) {
            return res;
        }
        return resourceService.getContainer(identifier).flatMap(this::getNearestResource);
    }

    private Predicate<Authorization> agentFilter(final Session session) {
        return auth -> auth.getAgentClass().contains(FOAF.Agent) || auth.getAgent().contains(session.getAgent()) ||
            auth.getAgentGroup().stream().anyMatch(isAgentInGroup(session.getAgent()));
    }

    private Predicate<Authorization> delegateFilter(final Session session) {
        return auth -> session.getDelegatedBy().filter(delegate -> !auth.getAgent().contains(delegate)).isPresent();
    }

    private Predicate<Authorization> getInheritedAuth(final IRI identifier) {
        return auth -> auth.getDefault().contains(identifier);
    }

    private Predicate<Authorization> getAccessToAuth(final IRI identifier) {
        return auth -> auth.getAccessTo().contains(identifier);
    }

    private Predicate<IRI> isAgentInGroup(final IRI agent) {
        return group -> resourceService.get(cleanIdentifier(group)).filter(res -> {
            try (final Stream<RDFTerm> triples = res.stream(Trellis.PreferUserManaged)
                    .filter(t -> t.getSubject().equals(group) && t.getPredicate().equals(VCARD.hasMember))
                    .map(Triple::getObject)) {
                return triples.anyMatch(agent::equals);
            }
        }).isPresent();
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
        LOGGER.debug("Checking ACL for: {}", resource.getIdentifier());
        final Optional<IRI> parent = resourceService.getContainer(resource.getIdentifier());
        if (resource.hasAcl()) {
            try (final Graph graph = getInstance().createGraph()) {
                resource.stream(Trellis.PreferAccessControl).forEach(graph::add);

                final List<Authorization> authorizations = getAuthorizationFromGraph(graph);

                if (!top && authorizations.stream().anyMatch(getInheritedAuth(resource.getIdentifier()))) {
                    return authorizations.stream().filter(getInheritedAuth(resource.getIdentifier()));
                }
                return authorizations.stream().filter(getAccessToAuth(resource.getIdentifier()));
            } catch (final Exception ex) {
                throw new RuntimeRepositoryException(ex);
            }
        }
        // Nothing here, check the parent
        LOGGER.debug("No ACL for {}; looking up parent resource", resource.getIdentifier());
        return parent.flatMap(resourceService::get).map(res -> getAllAuthorizationsFor(res, false))
            .orElseGet(Stream::empty);
    }
}
