/*
 * Copyright Amherst College
 *
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
package edu.amherst.acdc.trellis.webac;

import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.empty;
import static org.slf4j.LoggerFactory.getLogger;

import edu.amherst.acdc.trellis.api.Resource;
import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.AgentService;
import edu.amherst.acdc.trellis.spi.Authorization;
import edu.amherst.acdc.trellis.spi.ResourceService;
import edu.amherst.acdc.trellis.spi.Session;
import edu.amherst.acdc.trellis.vocabulary.ACL;
import edu.amherst.acdc.trellis.vocabulary.Trellis;

import java.util.List;
import java.util.Objects;
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

    private ResourceService service;

    private AgentService agentSvc;

    @Override
    public synchronized void bind(final ResourceService service) {
        requireNonNull(service, "A non-null ResourceService must be provided!");
        LOGGER.info("Binding ResourceService to the AuthorizationService");
        this.service = service;
    }

    @Override
    public synchronized void unbind(final ResourceService service) {
        if (Objects.equals(this.service, service)) {
            LOGGER.info("Unbinding ResourceService to the AuthorizationService");
            this.service = null;
        }
    }

    @Override
    public synchronized void bind(final AgentService service) {
        requireNonNull(service, "A non-null AgentService must be provided!");
        LOGGER.info("Binding AgentService to the AuthorizationService");
        this.agentSvc = service;
    }

    @Override
    public synchronized void unbind(final AgentService service) {
        if (Objects.equals(this.agentSvc, service)) {
            LOGGER.info("Unbinding AgentService to the AuthorizationService");
            this.agentSvc = null;
        }
    }

    @Override
    public Optional<IRI> findAclFor(final Session session, final IRI identifier) {
        final Optional<Resource> resource = getResourceService().flatMap(svc -> svc.get(identifier));
        return ofNullable(resource.flatMap(Resource::getAcl)
            .orElseGet(() -> resource.flatMap(Resource::getContainedBy).flatMap(id -> findAclFor(session, id))
                .orElse(null)));
    }

    @Override
    public Optional<Resource> findAncestorWithAccessControl(final Session session, final IRI identifier) {
        final Optional<Resource> resource = getResourceService().flatMap(svc -> svc.get(identifier));
        return ofNullable(resource.filter(res -> res.getAcl().isPresent())
                .orElseGet(() -> resource.flatMap(Resource::getContainedBy)
                    .flatMap(id -> findAncestorWithAccessControl(session, id)).orElse(null)));
    }

    @Override
    public Stream<Authorization> getAuthorizations(final Session session, final IRI identifier) {
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
                    .map(resource -> getAllAuthorizationsFor(session, resource)
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
        return auth -> session.getDelegatedBy().isPresent() &&
            !auth.getAgent().contains(session.getDelegatedBy().get());
    }

    private List<IRI> getGroups(final IRI agent) {
        return getAgentService().map(svc -> svc.getGroups(agent).collect(toList())).orElse(emptyList());
    }

    private Stream<Authorization> getAllAuthorizationsFor(final Session session, final Resource resource) {
        return resource.getAcl().map(acl -> getAuthorizations(session, acl).filter(hasAccess(resource)))
            .orElseGet(() -> resource.getContainedBy().flatMap(id -> findAncestorWithAccessControl(session, id))
                    .map(ancestor -> ancestor.getAcl().map(id -> getAuthorizations(session, id)).orElse(empty())
                        .filter(hasAccess(ancestor))).orElse(empty()));
    }

    private synchronized Optional<AgentService> getAgentService() {
        return ofNullable(agentSvc);
    }

    private synchronized Optional<ResourceService> getResourceService() {
        return ofNullable(service);
    }
}
