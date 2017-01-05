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
import static java.util.Optional.of;
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

    private final Session session;

    /**
     * Create a WebAC service
     * @param session the session
     * @param service the resource service
     */
    public WebACService(final Session session, final ResourceService service) {
        this.session = session;
        this.service = service;
    }

    @Override
    public Boolean canRead(final Session session, final IRI identifier) {
        return true;
    }

    @Override
    public Boolean canWrite(final Session session, final IRI identifier) {
        return true;
    }

    @Override
    public Boolean canControl(final Session session, final IRI identifier) {
        return true;
    }

    @Override
    public Optional<IRI> findAclFor(final IRI identifier) {
        final Resource resource = service.find(session, identifier);
        final Optional<IRI> acl = resource.getAccessControl();
        if (acl.isPresent()) {
            return acl;
        }

        final Optional<IRI> parent = resource.getParent();
        if (parent.isPresent()) {
            return findAclFor(parent.get());
        }

        return empty();
    }

    @Override
    public Optional<IRI> findAncestorWithAccessControl(final IRI identifier) {
        final Resource resource = service.find(session, identifier);
        final Optional<IRI> acl = resource.getAccessControl();
        if (acl.isPresent()) {
            return of(resource.getIdentifier());
        }

        final Optional<IRI> parent = resource.getParent();
        if (parent.isPresent()) {
            return findAncestorWithAccessControl(parent.get());
        }

        return empty();
    }

    @Override
    public Stream<Authorization> getAuthorizations(final IRI identifier) {
        final Resource acl = service.find(session, identifier);
        return acl.getChildren().flatMap(uri -> {
            final Resource auth = service.find(session, uri);
            if (auth.getTypes().anyMatch(ACL.Authorization::equals)) {
                final Graph graph = rdf.createGraph();
                auth.stream(USER_MANAGED).filter(triple ->
                        triple.getPredicate().getIRIString().startsWith(ACL.uri))
                    .forEach(graph::add);
                return Stream.of(new Authorization(uri, graph));
            }
            return Stream.empty();
        });
    }
}
