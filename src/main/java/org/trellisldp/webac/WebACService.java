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

import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.empty;
import static org.slf4j.LoggerFactory.getLogger;

import org.trellisldp.api.Resource;
import org.trellisldp.spi.AccessControlService;
import org.trellisldp.spi.AgentService;
import org.trellisldp.spi.Authorization;
import org.trellisldp.spi.ResourceService;
import org.trellisldp.spi.Session;
import org.trellisldp.vocabulary.ACL;
import org.trellisldp.vocabulary.Trellis;

import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.Quad;
import org.apache.commons.rdf.api.RDF;
import org.slf4j.Logger;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final Logger LOGGER = getLogger(WebACService.class);

    private static final RDF rdf = ServiceLoader.load(RDF.class).iterator().next();

    private static final Predicate<Resource> isAuthorization = resource ->
        resource.getTypes().anyMatch(ACL.Authorization::equals);

    private static final Predicate<Authorization> hasAccess(final Resource resource) {
        return authorization -> authorization.getAccessTo().contains(resource.getIdentifier()) ||
                resource.getTypes().anyMatch(authorization.getAccessToClass()::contains);
    }

    private final ResourceService service;

    private final AgentService agentSvc;

    /**
     * Create a WebAC-base authorization service
     * @param resourceService the resource service
     * @param agentService the agent service
     */
    public WebACService(final ResourceService resourceService, final AgentService agentService) {
        this.service = resourceService;
        this.agentSvc = agentService;
    }

    @Override
    public Optional<IRI> findAclFor(final IRI identifier) {
        return getResourceService().flatMap(svc -> {
            final Optional<Resource> res = svc.get(identifier);
            if (res.flatMap(Resource::getAcl).isPresent()) {
                return res.flatMap(Resource::getAcl);
            }
            return svc.getContainer(identifier).flatMap(this::findAclFor);
        });
    }

    @Override
    public Optional<Resource> findAncestorWithAccessControl(final IRI identifier) {
        return getResourceService().flatMap(svc -> {
            final Optional<Resource> res = svc.get(identifier);
            if (res.flatMap(Resource::getAcl).isPresent()) {
                return res;
            }
            return svc.getContainer(identifier).flatMap(this::findAncestorWithAccessControl);
        });
    }

    @Override
    public Stream<Authorization> getAuthorizations(final IRI identifier) {
        return getResourceService().flatMap(svc -> svc.get(identifier)).map(resource ->
            resource.getContains().parallel().unordered()
                .map(id -> getResourceService().flatMap(svc -> svc.get(id)))
                .filter(Optional::isPresent).map(Optional::get).filter(isAuthorization).map(auth -> {
                    final Graph graph = rdf.createGraph();
                    auth.stream().filter(quad -> quad.getGraphName().filter(Trellis.PreferUserManaged::equals)
                            .isPresent() && quad.getPredicate().getIRIString().startsWith(ACL.uri))
                        .map(Quad::asTriple).forEach(graph::add);
                    return Authorization.from(auth.getIdentifier(), graph);
                })).orElse(empty());
    }

    @Override
    public Boolean anyMatch(final Session session, final IRI identifier, final Predicate<IRI> predicate) {
        requireNonNull(session, "A non-null session must be provided!");
        requireNonNull(predicate, "A non-null predicate must be provided!");

        if (getAgentService().filter(svc -> svc.isAdmin(session.getAgent())).isPresent()) {
            return true;
        }

        return getResourceService().flatMap(svc -> svc.get(identifier))
                    .map(resource -> getAllAuthorizationsFor(resource)
                        .filter(delegateFilter(session).negate())
                        .filter(agentGroupFilter(session, getGroups(session.getAgent()))))
                    .orElse(empty()).peek(auth -> LOGGER.debug(auth.getIdentifier().getIRIString()))
                    .anyMatch(auth -> auth.getMode().stream().anyMatch(predicate));
    }

    private Predicate<Authorization> agentGroupFilter(final Session session, final List<IRI> agentGroups) {
        return auth -> auth.getAgent().contains(session.getAgent()) ||
            agentGroups.stream().anyMatch(auth.getAgentGroup()::contains);
    }

    private Predicate<Authorization> delegateFilter(final Session session) {
        return auth -> session.getDelegatedBy().filter(delegate -> !auth.getAgent().contains(delegate)).isPresent();
    }

    private List<IRI> getGroups(final IRI agent) {
        return getAgentService().map(svc -> svc.getGroups(agent).collect(toList())).orElse(emptyList());
    }

    private Stream<Authorization> getAllAuthorizationsFor(final Resource resource) {
        return resource.getAcl().map(acl -> getAuthorizations(acl).filter(hasAccess(resource)))
            .orElseGet(() -> getResourceService()
                .flatMap(svc -> svc.getContainer(resource.getIdentifier()))
                .flatMap(this::findAncestorWithAccessControl)
                .map(ancestor -> ancestor.getAcl().map(this::getAuthorizations).orElse(empty())
                    .filter(hasAccess(ancestor)))
                .orElse(empty()));
    }

    private Optional<AgentService> getAgentService() {
        return ofNullable(agentSvc);
    }

    private Optional<ResourceService> getResourceService() {
        return ofNullable(service);
    }
}
