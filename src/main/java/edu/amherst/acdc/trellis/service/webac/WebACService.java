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
package edu.amherst.acdc.trellis.service.webac;

import static java.util.Optional.empty;
import static edu.amherst.acdc.trellis.api.Resource.TripleContext.USER_MANAGED;

import java.util.Optional;
import java.util.stream.Stream;

import edu.amherst.acdc.trellis.api.Resource;
import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.Authorization;
import edu.amherst.acdc.trellis.spi.ResourceService;
import edu.amherst.acdc.trellis.spi.Session;
import edu.amherst.acdc.trellis.vocabulary.ACL;
import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.jena.JenaRDF;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final RDF rdf = new JenaRDF();

    private final ResourceService service;

    /**
     * Create a WebAC service
     * @param service the resource service
     */
    public WebACService(final ResourceService service) {
        this.service = service;
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
        final Optional<Resource> resource = service.find(identifier);
        if (resource.isPresent()) {
            final Optional<IRI> acl = resource.get().getAccessControl();
            if (acl.isPresent()) {
                return acl;
            }

            final Optional<IRI> parent = resource.get().getParent();
            if (parent.isPresent()) {
                return findAclFor(parent.get());
            }
        }
        return empty();
    }

    @Override
    public Optional<Resource> findAncestorWithAccessControl(final IRI identifier) {
        final Optional<Resource> resource = service.find(identifier);
        if (resource.isPresent()) {
            if (resource.get().getAccessControl().isPresent()) {
                return resource;
            }

            final Optional<IRI> parent = resource.get().getParent();
            if (parent.isPresent()) {
                return findAncestorWithAccessControl(parent.get());
            }
        }

        return empty();
    }

    @Override
    public Stream<Authorization> getAuthorizations(final IRI identifier) {
        final Optional<Resource> acl = service.find(identifier);
        if (acl.isPresent()) {
            return acl.get().getChildren().parallel().unordered().flatMap(uri -> {
                final Optional<Resource> auth = service.find(uri);
                if (auth.isPresent()) {
                    if (auth.get().getTypes().anyMatch(ACL.Authorization::equals)) {
                        final Graph graph = rdf.createGraph();
                        auth.get().stream(USER_MANAGED).filter(triple ->
                                triple.getPredicate().getIRIString().startsWith(ACL.uri))
                            .forEach(graph::add);
                        return Stream.of(new Authorization(uri, graph));
                    }
                }
                return Stream.empty();
            });
        }
        return Stream.empty();
    }

    private Boolean canPerformOperation(final Session session, final IRI identifier, final IRI mode) {
        // TODO -- add some sort of admin short-circut
        //if (session.isAdmin()) {
            //return true;
        //}

        final Optional<Resource> resource = service.find(identifier);
        if (resource.isPresent()) {
            return getAllAuthorizationsFor(resource.get())
                    .filter(auth -> auth.getMode().contains(mode))
                    .anyMatch(auth -> {
                        if (session.getDelegatedBy().isPresent() &&
                                !auth.getAgent().contains(session.getDelegatedBy().get())) {
                            return false;
                        }
                        return auth.getAgent().contains(session.getUser()) ||
                                session.getGroups().stream().anyMatch(auth.getAgentGroup()::contains);
                    });
        }
        return false;
    }

    private Stream<Authorization> getAllAuthorizationsFor(final Resource resource) {
        if (resource.getAccessControl().isPresent()) {
            return getAuthorizations(resource.getAccessControl().get())
                    .filter(auth -> auth.getAccessTo().contains(resource.getIdentifier()) ||
                                resource.getTypes().anyMatch(auth.getAccessToClass()::contains));
        } else if (resource.getParent().isPresent()) {
            final Optional<Resource> ancestor = findAncestorWithAccessControl(resource.getParent().get());
            if (ancestor.isPresent()) {
                return getAuthorizations(ancestor.get().getAccessControl().get())
                            .filter(auth -> auth.getAccessTo().contains(ancestor.get().getIdentifier()) ||
                                    resource.getTypes().anyMatch(auth.getAccessToClass()::contains));
            }
        }
        return Stream.empty();
    }
}
