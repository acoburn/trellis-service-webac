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

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.trellisldp.vocabulary.RDF.type;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.trellisldp.api.Resource;
import org.trellisldp.spi.AccessControlService;
import org.trellisldp.spi.AgentService;
import org.trellisldp.spi.ResourceService;
import org.trellisldp.spi.Session;
import org.trellisldp.vocabulary.ACL;
import org.trellisldp.vocabulary.Trellis;
import org.apache.commons.rdf.api.Graph;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.api.Triple;
import org.apache.commons.rdf.simple.SimpleRDF;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author acoburn
 */
@RunWith(MockitoJUnitRunner.class)
public class WebACServiceTest {

    private static final RDF rdf = new SimpleRDF();

    @Mock
    private ResourceService mockResourceService;

    @Mock
    private AgentService mockAgentService;

    @Mock
    private Session mockSession;

    @Mock
    private Resource mockResource, mockChildResource, mockParentResource, mockRootResource,
                mockPrivateAclResource, mockPublicAclResource, mockAuthResource1,
                mockAuthResource2, mockAuthResource3, mockAuthResource4, mockAuthResource5,
                mockAuthResource6, mockAuthResource7, mockAuthResource8;

    private AccessControlService testService;

    private final static IRI resourceIRI = rdf.createIRI("trellis:repository/parent/child/resource");

    private final static IRI childIRI = rdf.createIRI("trellis:repository/parent/child");

    private final static IRI parentIRI = rdf.createIRI("trellis:repository/parent");

    private final static IRI rootIRI = rdf.createIRI("trellis:repository");

    private final static IRI authIRI1 = rdf.createIRI("trellis:repository/acl/public/auth1");

    private final static IRI authIRI2 = rdf.createIRI("trellis:repository/acl/public/auth2");

    private final static IRI authIRI3 = rdf.createIRI("trellis:repository/acl/public/auth3");

    private final static IRI authIRI4 = rdf.createIRI("trellis:repository/acl/public/auth4");

    private final static IRI authIRI5 = rdf.createIRI("trellis:repository/acl/private/auth5");

    private final static IRI authIRI6 = rdf.createIRI("trellis:repository/acl/private/auth6");

    private final static IRI authIRI7 = rdf.createIRI("trellis:repository/acl/private/auth7");

    private final static IRI authIRI8 = rdf.createIRI("trellis:repository/acl/private/auth8");

    private final static IRI bseegerIRI = rdf.createIRI("info:user/bseeger");

    private final static IRI acoburnIRI = rdf.createIRI("info:user/acoburn");

    private final static IRI agentIRI = rdf.createIRI("info:user/agent");

    private static Graph getGraph1() {
        final Graph graph1 = rdf.createGraph();
        graph1.add(rdf.createTriple(authIRI1, type, ACL.Authorization));
        graph1.add(rdf.createTriple(authIRI1, ACL.mode, ACL.Read));
        graph1.add(rdf.createTriple(authIRI1, ACL.agent, bseegerIRI));
        graph1.add(rdf.createTriple(authIRI1, ACL.accessTo, childIRI));

        graph1.add(rdf.createTriple(authIRI2, type, ACL.Authorization));
        graph1.add(rdf.createTriple(authIRI2, ACL.mode, ACL.Read));
        graph1.add(rdf.createTriple(authIRI2, ACL.mode, ACL.Write));
        graph1.add(rdf.createTriple(authIRI2, ACL.mode, ACL.Control));
        graph1.add(rdf.createTriple(authIRI2, ACL.agent, bseegerIRI));
        graph1.add(rdf.createTriple(authIRI2, ACL.agent, agentIRI));
        graph1.add(rdf.createTriple(authIRI2, ACL.accessTo, childIRI));

        graph1.add(rdf.createTriple(authIRI4, ACL.agent, agentIRI));
        graph1.add(rdf.createTriple(authIRI4, type, ACL.Authorization));
        return graph1;
    }

    private static Graph getGraph2() {
        final Graph graph2 = rdf.createGraph();
        graph2.add(rdf.createTriple(authIRI5, type, ACL.Authorization));
        graph2.add(rdf.createTriple(authIRI5, ACL.accessTo, rootIRI));
        graph2.add(rdf.createTriple(authIRI5, ACL.agent, bseegerIRI));
        graph2.add(rdf.createTriple(authIRI5, ACL.mode, ACL.Read));
        graph2.add(rdf.createTriple(authIRI5, ACL.mode, ACL.Append));

        graph2.add(rdf.createTriple(authIRI6, type, ACL.Authorization));
        graph2.add(rdf.createTriple(authIRI6, ACL.agent, acoburnIRI));
        graph2.add(rdf.createTriple(authIRI6, ACL.accessTo, rootIRI));
        graph2.add(rdf.createTriple(authIRI6, ACL.mode, ACL.Append));

        graph2.add(rdf.createTriple(authIRI8, type, ACL.Authorization));
        graph2.add(rdf.createTriple(authIRI8, ACL.agent, agentIRI));
        graph2.add(rdf.createTriple(authIRI8, ACL.accessTo, rootIRI));
        graph2.add(rdf.createTriple(authIRI8, ACL.mode, ACL.Read));
        graph2.add(rdf.createTriple(authIRI8, ACL.mode, ACL.Write));
        return graph2;
    }

    @Before
    public void setUp() {

        testService = new WebACService(mockResourceService, mockAgentService);

        when(mockChildResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv ->
                getGraph1().stream().map(t -> (Triple)t));
        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv ->
                getGraph2().stream().map(t -> (Triple)t));

        when(mockResourceService.get(eq(resourceIRI))).thenReturn(of(mockResource));
        when(mockResourceService.get(eq(childIRI))).thenReturn(of(mockChildResource));
        when(mockResourceService.get(eq(parentIRI))).thenReturn(of(mockParentResource));
        when(mockResourceService.get(eq(rootIRI))).thenReturn(of(mockRootResource));
        when(mockResourceService.getContainer(resourceIRI)).thenReturn(of(childIRI));
        when(mockResourceService.getContainer(childIRI)).thenReturn(of(parentIRI));
        when(mockResourceService.getContainer(parentIRI)).thenReturn(of(rootIRI));

        when(mockResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.empty());
        when(mockParentResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.empty());

        when(mockResource.getIdentifier()).thenReturn(resourceIRI);
        when(mockChildResource.getIdentifier()).thenReturn(childIRI);
        when(mockParentResource.getIdentifier()).thenReturn(parentIRI);
        when(mockRootResource.getIdentifier()).thenReturn(rootIRI);

        when(mockAgentService.isAdmin(any(IRI.class))).thenReturn(false);
        when(mockAgentService.getGroups(any(IRI.class))).thenAnswer(inv -> Stream.empty());

        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(empty());
    }

    @Test
    public void testCanRead1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canRead(mockSession, resourceIRI));
        assertFalse(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanRead2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanRead3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canWrite(mockSession, resourceIRI));
        assertFalse(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertTrue(testService.canWrite(mockSession, parentIRI));
        assertTrue(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanControl1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canControl(mockSession, resourceIRI));
        assertFalse(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanControl2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canControl(mockSession, resourceIRI));
        assertTrue(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanControl3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canControl(mockSession, resourceIRI));
        assertTrue(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertTrue(testService.canAppend(mockSession, parentIRI));
        assertTrue(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertTrue(testService.canAppend(mockSession, parentIRI));
        assertTrue(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertFalse(testService.canAppend(mockSession, parentIRI));
        assertFalse(testService.canAppend(mockSession, rootIRI));
    }
}
