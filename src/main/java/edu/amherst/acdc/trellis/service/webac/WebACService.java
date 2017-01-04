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

import static edu.amherst.acdc.trellis.api.Resource.TripleContext.FEDORA_EMBED_RESOURCES;
import static edu.amherst.acdc.trellis.api.Resource.TripleContext.LDP_CONTAINMENT;
import static edu.amherst.acdc.trellis.api.Resource.TripleContext.USER_MANAGED;
import static edu.amherst.acdc.trellis.vocabulary.RDF.type;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static java.util.stream.Collectors.toSet;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import edu.amherst.acdc.trellis.api.Resource;
import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.ResourceService;
import edu.amherst.acdc.trellis.spi.Authorization;
import edu.amherst.acdc.trellis.spi.Session;
import edu.amherst.acdc.trellis.vocabulary.ACL;
import org.apache.commons.rdf.api.BlankNodeOrIRI;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.Triple;
import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.simple.SimpleRDF;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

    private static final RDF rdf = new SimpleRDF();

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
        final List<Resource.TripleCategory> types = new ArrayList<>();
        types.add(FEDORA_EMBED_RESOURCES);
        types.add(USER_MANAGED);
        types.add(LDP_CONTAINMENT);
        final Graph graph = rdf.createGraph();
        acl.stream(types).forEach(graph::add);

        final Set<BlankNodeOrIRI> subjects = graph.stream(null, type, ACL.Authorization)
            .map(Triple::getSubject)
            .collect(toSet());

        //return subjects.stream().map(subject -> {
//            graph.stream(subject, ACL.mode, null).

        //});

        return Stream.empty();
    }
}
