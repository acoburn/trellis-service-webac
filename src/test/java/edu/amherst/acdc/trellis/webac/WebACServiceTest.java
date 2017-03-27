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
import static edu.amherst.acdc.trellis.vocabulary.RDF.type;
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
import edu.amherst.acdc.trellis.vocabulary.ACL;
import edu.amherst.acdc.trellis.vocabulary.PROV;
import edu.amherst.acdc.trellis.vocabulary.Trellis;
import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.simple.SimpleRDF;

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

    private final AccessControlService testService = new WebACService();

    private final IRI resourceIRI = rdf.createIRI("trellis:repository/parent/child/resource");

    private final IRI childIRI = rdf.createIRI("trellis:repository/parent/child");

    private final IRI parentIRI = rdf.createIRI("trellis:repository/parent");

    private final IRI rootIRI = rdf.createIRI("trellis:repository");

    private final IRI publicAclIRI = rdf.createIRI("trellis:repository/acl/public");

    private final IRI privateAclIRI = rdf.createIRI("trellis:repository/acl/private");

    private final IRI authIRI1 = rdf.createIRI("trellis:repository/acl/public/auth1");

    private final IRI authIRI2 = rdf.createIRI("trellis:repository/acl/public/auth2");

    private final IRI authIRI3 = rdf.createIRI("trellis:repository/acl/public/auth3");

    private final IRI authIRI4 = rdf.createIRI("trellis:repository/acl/public/auth4");

    private final IRI authIRI5 = rdf.createIRI("trellis:repository/acl/private/auth5");

    private final IRI authIRI6 = rdf.createIRI("trellis:repository/acl/private/auth6");

    private final IRI authIRI7 = rdf.createIRI("trellis:repository/acl/private/auth7");

    private final IRI authIRI8 = rdf.createIRI("trellis:repository/acl/private/auth8");

    private final IRI bseegerIRI = rdf.createIRI("info:user/bseeger");

    private final IRI acoburnIRI = rdf.createIRI("info:user/acoburn");

    private final IRI agentIRI = rdf.createIRI("info:user/agent");

    @Before
    public void setUp() {
        testService.bind(mockResourceService);
        testService.bind(mockAgentService);

        when(mockResourceService.get(eq(resourceIRI))).thenReturn(of(mockResource));
        when(mockResourceService.get(eq(childIRI))).thenReturn(of(mockChildResource));
        when(mockResourceService.get(eq(parentIRI))).thenReturn(of(mockParentResource));
        when(mockResourceService.get(eq(rootIRI))).thenReturn(of(mockRootResource));
        when(mockResourceService.get(eq(publicAclIRI))).thenReturn(of(mockPublicAclResource));
        when(mockResourceService.get(eq(privateAclIRI))).thenReturn(of(mockPrivateAclResource));
        when(mockResourceService.get(eq(authIRI1))).thenReturn(of(mockAuthResource1));
        when(mockResourceService.get(eq(authIRI2))).thenReturn(of(mockAuthResource2));
        when(mockResourceService.get(eq(authIRI3))).thenReturn(of(mockAuthResource3));
        when(mockResourceService.get(eq(authIRI4))).thenReturn(of(mockAuthResource4));
        when(mockResourceService.get(eq(authIRI5))).thenReturn(of(mockAuthResource5));
        when(mockResourceService.get(eq(authIRI6))).thenReturn(of(mockAuthResource6));
        when(mockResourceService.get(eq(authIRI7))).thenReturn(of(mockAuthResource7));
        when(mockResourceService.get(eq(authIRI8))).thenReturn(of(mockAuthResource8));

        when(mockResourceService.getContainer(resourceIRI)).thenReturn(of(childIRI));
        when(mockResourceService.getContainer(childIRI)).thenReturn(of(parentIRI));
        when(mockResourceService.getContainer(parentIRI)).thenReturn(of(rootIRI));
        when(mockResourceService.getContainer(rootIRI)).thenReturn(empty());

        when(mockResource.getAcl()).thenReturn(empty());
        when(mockChildResource.getAcl()).thenReturn(of(publicAclIRI));
        when(mockParentResource.getAcl()).thenReturn(empty());
        when(mockRootResource.getAcl()).thenReturn(of(privateAclIRI));

        when(mockResource.getTypes()).thenAnswer(inv -> Stream.empty());
        when(mockChildResource.getTypes()).thenAnswer(inv -> Stream.empty());
        when(mockParentResource.getTypes()).thenAnswer(inv -> Stream.empty());
        when(mockRootResource.getTypes()).thenAnswer(inv -> Stream.empty());

        when(mockResource.getIdentifier()).thenReturn(resourceIRI);
        when(mockChildResource.getIdentifier()).thenReturn(childIRI);
        when(mockParentResource.getIdentifier()).thenReturn(parentIRI);
        when(mockRootResource.getIdentifier()).thenReturn(rootIRI);

        when(mockAuthResource1.getIdentifier()).thenReturn(authIRI1);
        when(mockAuthResource1.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource1.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI1, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI1, ACL.mode, ACL.Read),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI1, ACL.agent, bseegerIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI1, ACL.accessTo, childIRI)));

        when(mockAuthResource2.getIdentifier()).thenReturn(authIRI2);
        when(mockAuthResource2.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource2.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI2, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI2, ACL.mode, ACL.Read),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI2, ACL.agent, acoburnIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI2, ACL.accessToClass, PROV.Activity)));

        when(mockAuthResource3.getIdentifier()).thenReturn(authIRI3);
        when(mockAuthResource3.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource3.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.mode, ACL.Read),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.mode, ACL.Write),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.mode, ACL.Control),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.agent, bseegerIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.agent, agentIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI3, ACL.accessTo, childIRI)));

        when(mockAuthResource4.getIdentifier()).thenReturn(authIRI4);
        when(mockAuthResource4.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource4.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI4, ACL.agent, agentIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI4, type, ACL.Authorization)));

        when(mockAuthResource5.getIdentifier()).thenReturn(authIRI5);
        when(mockAuthResource5.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource5.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI5, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI5, ACL.accessTo, rootIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI5, ACL.agent, bseegerIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI5, ACL.mode, ACL.Read),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI5, ACL.mode, ACL.Append)));

        when(mockAuthResource6.getIdentifier()).thenReturn(authIRI6);
        when(mockAuthResource6.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource6.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI6, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI6, ACL.agent, acoburnIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI6, ACL.accessTo, rootIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI6, ACL.mode, ACL.Append)));

        when(mockAuthResource7.getIdentifier()).thenReturn(authIRI7);
        when(mockAuthResource7.getTypes()).thenAnswer(inv -> Stream.empty());
        when(mockAuthResource7.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI7, ACL.agent, acoburnIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI7, ACL.accessTo, rootIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI7, ACL.mode, ACL.Read)));

        when(mockAuthResource8.getIdentifier()).thenReturn(authIRI8);
        when(mockAuthResource8.getTypes()).thenAnswer(inv -> Stream.of(ACL.Authorization));
        when(mockAuthResource8.stream()).thenAnswer(inv -> Stream.of(
                rdf.createQuad(Trellis.PreferUserManaged, authIRI8, type, ACL.Authorization),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI8, ACL.agent, agentIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI8, ACL.accessTo, rootIRI),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI8, ACL.mode, ACL.Read),
                rdf.createQuad(Trellis.PreferUserManaged, authIRI8, ACL.mode, ACL.Write)));

        when(mockAgentService.isAdmin(any(IRI.class))).thenReturn(false);
        when(mockAgentService.getGroups(any(IRI.class))).thenAnswer(inv -> Stream.empty());

        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(empty());

        when(mockPublicAclResource.getContains()).thenAnswer(inv -> Stream.of(authIRI1, authIRI2, authIRI3, authIRI4));
        when(mockPrivateAclResource.getContains()).thenAnswer(inv -> Stream.of(authIRI5, authIRI6, authIRI7, authIRI8));
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
        assertEquals(4, testService.getAuthorizations(mockSession, publicAclIRI).count());
        assertEquals(3, testService.getAuthorizations(mockSession, privateAclIRI).count());
    }
}
