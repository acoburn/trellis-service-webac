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

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import edu.amherst.acdc.trellis.api.Resource;
import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.AgentService;
import edu.amherst.acdc.trellis.spi.ResourceService;
import edu.amherst.acdc.trellis.spi.Session;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.jena.JenaRDF;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * @author acoburn
 */
@RunWith(MockitoJUnitRunner.class)
public class WebACServiceTest {

    private static final RDF rdf = new JenaRDF();

    @Mock
    private ResourceService mockResourceService;

    @Mock
    private AgentService mockAgentService;

    @Mock
    private Session mockSession;

    @Mock
    private Resource mockResource, mockChildResource, mockParentResource, mockRootResource;

    private final AccessControlService testService = new WebACService();

    private final IRI resourceIRI = rdf.createIRI("info:trellis/parent/child/resource");

    private final IRI childIRI = rdf.createIRI("info:trellis/parent/child");

    private final IRI parentIRI = rdf.createIRI("info:trellis/parent");

    private final IRI rootIRI = rdf.createIRI("info:trellis");

    private final IRI publicAclIRI = rdf.createIRI("info:trellis/acl/public");

    private final IRI privateAclIRI = rdf.createIRI("info:trellis/acl/private");

    private final IRI authIRI1 = rdf.createIRI("info:trellis/acl/public/auth1");

    private final IRI authIRI2 = rdf.createIRI("info:trellis/acl/public/auth2");

    private final IRI authIRI3 = rdf.createIRI("info:trellis/acl/public/auth3");

    private final IRI authIRI4 = rdf.createIRI("info:trellis/acl/public/auth4");

    private final IRI authIRI5 = rdf.createIRI("info:trellis/acl/private/auth5");

    private final IRI authIRI6 = rdf.createIRI("info:trellis/acl/private/auth6");

    private final IRI authIRI7 = rdf.createIRI("info:trellis/acl/private/auth7");

    private final IRI authIRI8 = rdf.createIRI("info:trellis/acl/private/auth8");

    private final IRI bseegerIRI = rdf.createIRI("info:user/bseeger");

    private final IRI acoburnIRI = rdf.createIRI("info:user/acoburn");

    private final IRI agentIRI = rdf.createIRI("info:user/agent");

    @Before
    public void setUp() {
        testService.bind(mockResourceService);
        testService.bind(mockAgentService);

        when(mockResourceService.find(any(Session.class), eq(resourceIRI))).thenReturn(of(mockResource));
        when(mockResourceService.find(any(Session.class), eq(childIRI))).thenReturn(of(mockChildResource));
        when(mockResourceService.find(any(Session.class), eq(parentIRI))).thenReturn(of(mockParentResource));
        when(mockResourceService.find(any(Session.class), eq(rootIRI))).thenReturn(of(mockRootResource));

        when(mockResource.getParent()).thenReturn(of(childIRI));
        when(mockChildResource.getParent()).thenReturn(of(parentIRI));
        when(mockParentResource.getParent()).thenReturn(of(rootIRI));
        when(mockRootResource.getParent()).thenReturn(empty());

        when(mockResource.getAccessControl()).thenReturn(empty());
        when(mockChildResource.getAccessControl()).thenReturn(of(publicAclIRI));
        when(mockParentResource.getAccessControl()).thenReturn(empty());
        when(mockRootResource.getAccessControl()).thenReturn(of(privateAclIRI));

        when(mockAgentService.isAdmin(any(IRI.class))).thenReturn(false);
        when(mockAgentService.getGroups(any(IRI.class))).thenReturn(Stream.empty());

        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(empty());
    }

    @Test
    public void testCanRead() {
        // TODO
        assertTrue(true);
    }

    @Test
    public void testCanWrite() {
        // TODO
        assertFalse(false);
    }

    @Test
    public void testCanControl() {
        // TODO
        assertTrue(true);
    }

    @Test
    public void testCanAppend() {
        // TODO
        assertTrue(true);
    }

    @Test
    public void testFindAcl() {
        assertEquals(of(publicAclIRI), testService.findAclFor(mockSession, resourceIRI));
        assertEquals(of(publicAclIRI), testService.findAclFor(mockSession, childIRI));
        assertEquals(of(privateAclIRI), testService.findAclFor(mockSession, parentIRI));
        assertEquals(of(privateAclIRI), testService.findAclFor(mockSession, rootIRI));
    }

    @Test
    public void testFindAncestor() {
        assertEquals(of(mockChildResource), testService.findAncestorWithAccessControl(mockSession, resourceIRI));
        assertEquals(of(mockChildResource), testService.findAncestorWithAccessControl(mockSession, childIRI));
        assertEquals(of(mockRootResource), testService.findAncestorWithAccessControl(mockSession, parentIRI));
        assertEquals(of(mockRootResource), testService.findAncestorWithAccessControl(mockSession, rootIRI));
    }

    @Test
    public void testGetAuthorizations() {
        // TODO
        assertTrue(true);
    }
}
