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
import static java.util.stream.Stream.of;
import static edu.amherst.acdc.trellis.api.Resource.TripleContext.USER_MANAGED;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import edu.amherst.acdc.trellis.api.Resource;
import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.AgentService;
import edu.amherst.acdc.trellis.spi.Authorization;
import edu.amherst.acdc.trellis.spi.ResourceService;
import edu.amherst.acdc.trellis.spi.Session;
import edu.amherst.acdc.trellis.vocabulary.ACL;
import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.jena.JenaRDF;
import org.slf4j.Logger;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final Logger LOGGER = getLogger(WebACService.class);

    private static final RDF rdf = new JenaRDF();

    private static Predicate<Resource> isAuthorization = resource ->
        resource.getTypes().anyMatch(ACL.Authorization::equals);

    private static Predicate<Authorization> hasAccess(final Resource resource) {
        return authorization -> authorization.getAccessTo().contains(resource.getIdentifier()) ||
                resource.getTypes().anyMatch(authorization.getAccessToClass()::contains);
    }

    private ResourceService service;

    private AgentService agentSvc;

    @Override
    public synchronized void bind(final ResourceService service) {
        requireNonNull(service, "A non-null ResourceService must be provided!");
        this.service = service;
    }

    @Override
    public synchronized void unbind(final ResourceService service) {
        if (this.service == service) {
            this.service = null;
        }
    }

    @Override
    public synchronized void bind(final AgentService service) {
        requireNonNull(service, "A non-null AgentService must be provided!");
        this.agentSvc = service;
    }

    @Override
    public synchronized void unbind(final AgentService service) {
        if (this.agentSvc == service) {
            this.agentSvc = null;
        }
    }

    @Override
    public Boolean canRead(final Session session, final IRI identifier) {
        return canPerformOperation(session, identifier, ACL.Read);
    }

    @Override
    public Boolean canWrite(final Session session, final IRI identifier) {
        return canPerformOperation(session, identifier, ACL.Write);
    }

    @Override
    public Boolean canControl(final Session session, final IRI identifier) {
        return canPerformOperation(session, identifier, ACL.Control);
    }

    @Override
    public Boolean canAppend(final Session session, final IRI identifier) {
        return canPerformOperation(session, identifier, ACL.Append);
    }

    @Override
    public Optional<IRI> findAclFor(final IRI identifier) {
        requireNonNull(identifier, "A non-null identifier must be provided!");
        final Optional<Resource> resource = ofNullable(service).flatMap(svc -> svc.find(identifier));
        return ofNullable(resource.flatMap(Resource::getAccessControl)
            .orElseGet(() -> resource.flatMap(Resource::getParent).flatMap(this::findAclFor).orElse(null)));
    }

    @Override
    public Optional<Resource> findAncestorWithAccessControl(final IRI identifier) {
        requireNonNull(identifier, "A non-null identifier must be provided!");
        final Optional<Resource> resource = ofNullable(service).flatMap(svc -> svc.find(identifier));
        return ofNullable(resource.filter(res -> res.getAccessControl().isPresent())
                .orElseGet(() -> resource.flatMap(Resource::getParent).flatMap(this::findAncestorWithAccessControl)
                    .orElse(null)));
    }

    @Override
    public Stream<Authorization> getAuthorizations(final IRI identifier) {
        requireNonNull(identifier, "A non-null identifier must be provided!");
        return ofNullable(service).flatMap(svc -> svc.find(identifier)).map(resource ->
            resource.getChildren().parallel().unordered().map(service::find).filter(Optional::isPresent)
                .map(Optional::get).filter(isAuthorization).flatMap(auth -> {
                    final Graph graph = rdf.createGraph();
                    auth.stream(USER_MANAGED).filter(triple -> triple.getPredicate().getIRIString().startsWith(ACL.uri))
                        .forEach(graph::add);
                    return of(new Authorization(auth.getIdentifier(), graph));
                })).orElse(empty());
    }

    private List<IRI> getGroups(final IRI agent) {
        return ofNullable(agentSvc).map(svc -> svc.getGroups(agent).collect(toList())).orElse(emptyList());
    }

    private Boolean canPerformOperation(final Session session, final IRI identifier, final IRI mode) {
        requireNonNull(session, "A non-null session must be provided!");
        requireNonNull(identifier, "A non-null identifier must be provided!");

        if (ofNullable(agentSvc).filter(svc -> svc.isAdmin(session.getAgent())).isPresent()) {
            return true;
        }

        final List<IRI> agentGroups = getGroups(session.getAgent());
        final List<IRI> delegatedGroups = session.getDelegatedBy().map(this::getGroups).orElse(emptyList());

        return ofNullable(service).flatMap(svc -> svc.find(identifier))
                    .map(resource -> getAllAuthorizationsFor(resource)
                    .filter(auth -> auth.getMode().contains(mode))
                    .anyMatch(auth -> {
                        if (session.getDelegatedBy().isPresent() &&
                                !auth.getAgent().contains(session.getDelegatedBy().get())) {
                            return false;
                        }
                        return auth.getAgent().contains(session.getAgent()) ||
                                agentGroups.stream().anyMatch(auth.getAgentGroup()::contains);
                    })).orElse(false);
    }

    private Stream<Authorization> getAllAuthorizationsFor(final Resource resource) {
        if (resource.getAccessControl().isPresent()) {
            return getAuthorizations(resource.getAccessControl().get()).filter(hasAccess(resource));
        }
        return resource.getParent().flatMap(this::findAncestorWithAccessControl).map(ancestor ->
            ancestor.getAccessControl().map(this::getAuthorizations).orElse(empty()).filter(hasAccess(ancestor)))
                .orElse(empty());
    }

}
