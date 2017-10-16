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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.stream.Stream;

import org.apache.commons.rdf.api.IRI;
import org.apache.commons.rdf.api.RDF;
import org.apache.commons.rdf.jena.JenaRDF;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.trellisldp.api.AccessControlService;
import org.trellisldp.api.Resource;
import org.trellisldp.api.ResourceService;
import org.trellisldp.api.Session;
import org.trellisldp.vocabulary.ACL;
import org.trellisldp.vocabulary.FOAF;
import org.trellisldp.vocabulary.PROV;
import org.trellisldp.vocabulary.Trellis;
import org.trellisldp.vocabulary.VCARD;

/**
 * @author acoburn
 */
@RunWith(JUnitPlatform.class)
public class WebACServiceTest {

    private static final RDF rdf = new JenaRDF();

    @Mock
    private ResourceService mockResourceService;

    @Mock
    private Session mockSession;

    @Mock
    private Resource mockResource, mockChildResource, mockParentResource, mockRootResource,
                mockPrivateAclResource, mockPublicAclResource, mockAuthResource1,
                mockAuthResource2, mockAuthResource3, mockAuthResource4, mockAuthResource5,
                mockAuthResource6, mockAuthResource7, mockAuthResource8, mockGroupResource;

    private AccessControlService testService;

    private final static IRI nonexistentIRI = rdf.createIRI("trellis:repository/parent/child/nonexistent");

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

    private final static IRI groupIRI = rdf.createIRI("trellis:repository/group/test");

    private final static IRI groupIRI2 = rdf.createIRI("trellis:repository/group/test/");

    @BeforeEach
    public void setUp() {
        initMocks(this);

        testService = new WebACService(mockResourceService);

        when(mockChildResource.hasAcl()).thenReturn(true);
        when(mockChildResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI1, type, ACL.Authorization),
                rdf.createTriple(authIRI1, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI1, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI1, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI2, type, ACL.Authorization),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI2, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI2, ACL.agent, agentIRI),
                rdf.createTriple(authIRI2, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI3, type, PROV.Activity),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI3, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI3, ACL.agent, agentIRI),
                rdf.createTriple(authIRI3, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI4, ACL.agent, agentIRI),
                rdf.createTriple(authIRI4, type, ACL.Authorization)));

        when(mockRootResource.hasAcl()).thenReturn(true);
        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI5, type, ACL.Authorization),
                rdf.createTriple(authIRI5, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI5, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI6, type, ACL.Authorization),
                rdf.createTriple(authIRI6, ACL.agent, acoburnIRI),
                rdf.createTriple(authIRI6, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI6, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI8, type, ACL.Authorization),
                rdf.createTriple(authIRI8, ACL.agent, agentIRI),
                rdf.createTriple(authIRI8, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Write)));

        when(mockResourceService.get(eq(nonexistentIRI))).thenReturn(empty());
        when(mockResourceService.get(eq(resourceIRI))).thenReturn(of(mockResource));
        when(mockResourceService.get(eq(childIRI))).thenReturn(of(mockChildResource));
        when(mockResourceService.get(eq(parentIRI))).thenReturn(of(mockParentResource));
        when(mockResourceService.get(eq(rootIRI))).thenReturn(of(mockRootResource));
        when(mockResourceService.get(eq(groupIRI))).thenReturn(of(mockGroupResource));
        when(mockResourceService.getContainer(nonexistentIRI)).thenReturn(of(resourceIRI));
        when(mockResourceService.getContainer(resourceIRI)).thenReturn(of(childIRI));
        when(mockResourceService.getContainer(childIRI)).thenReturn(of(parentIRI));
        when(mockResourceService.getContainer(parentIRI)).thenReturn(of(rootIRI));

        when(mockResource.getIdentifier()).thenReturn(resourceIRI);
        when(mockChildResource.getIdentifier()).thenReturn(childIRI);
        when(mockParentResource.getIdentifier()).thenReturn(parentIRI);
        when(mockRootResource.getIdentifier()).thenReturn(rootIRI);
        when(mockResource.hasAcl()).thenReturn(false);
        when(mockParentResource.hasAcl()).thenReturn(false);

        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(empty());
    }

    @Test
    public void testCanRead1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canRead(mockSession, nonexistentIRI));
        assertFalse(testService.canRead(mockSession, resourceIRI));
        assertFalse(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanRead2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canRead(mockSession, nonexistentIRI));
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanRead3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canRead(mockSession, nonexistentIRI));
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canWrite(mockSession, nonexistentIRI));
        assertFalse(testService.canWrite(mockSession, resourceIRI));
        assertFalse(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canWrite(mockSession, nonexistentIRI));
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanWrite3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canWrite(mockSession, nonexistentIRI));
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertTrue(testService.canWrite(mockSession, parentIRI));
        assertTrue(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testCanControl1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canWrite(mockSession, nonexistentIRI));
        assertFalse(testService.canControl(mockSession, resourceIRI));
        assertFalse(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanControl2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertTrue(testService.canControl(mockSession, nonexistentIRI));
        assertTrue(testService.canControl(mockSession, resourceIRI));
        assertTrue(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanControl3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertTrue(testService.canControl(mockSession, nonexistentIRI));
        assertTrue(testService.canControl(mockSession, resourceIRI));
        assertTrue(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend1() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        assertFalse(testService.canAppend(mockSession, nonexistentIRI));
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertTrue(testService.canAppend(mockSession, parentIRI));
        assertTrue(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend2() {
        when(mockSession.getAgent()).thenReturn(bseegerIRI);
        assertFalse(testService.canAppend(mockSession, nonexistentIRI));
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertTrue(testService.canAppend(mockSession, parentIRI));
        assertTrue(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testCanAppend3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        assertFalse(testService.canAppend(mockSession, nonexistentIRI));
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertFalse(testService.canAppend(mockSession, parentIRI));
        assertFalse(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testAdmin1() {
        when(mockSession.getAgent()).thenReturn(Trellis.RepositoryAdministrator);
        assertTrue(testService.canAppend(mockSession, nonexistentIRI));
        assertTrue(testService.canAppend(mockSession, resourceIRI));
        assertTrue(testService.canAppend(mockSession, childIRI));
        assertTrue(testService.canAppend(mockSession, parentIRI));
        assertTrue(testService.canAppend(mockSession, rootIRI));
        assertTrue(testService.canControl(mockSession, nonexistentIRI));
        assertTrue(testService.canControl(mockSession, resourceIRI));
        assertTrue(testService.canControl(mockSession, childIRI));
        assertTrue(testService.canControl(mockSession, parentIRI));
        assertTrue(testService.canControl(mockSession, rootIRI));
        assertTrue(testService.canWrite(mockSession, nonexistentIRI));
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertTrue(testService.canWrite(mockSession, parentIRI));
        assertTrue(testService.canWrite(mockSession, rootIRI));
        assertTrue(testService.canRead(mockSession, nonexistentIRI));
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testDelegate1() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(of(acoburnIRI));

        assertFalse(testService.canRead(mockSession, resourceIRI));
        assertFalse(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));

        assertFalse(testService.canWrite(mockSession, resourceIRI));
        assertFalse(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testDelegate2() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        when(mockSession.getDelegatedBy()).thenReturn(of(agentIRI));

        assertFalse(testService.canRead(mockSession, resourceIRI));
        assertFalse(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));

        assertFalse(testService.canWrite(mockSession, resourceIRI));
        assertFalse(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testDelegate3() {
        when(mockSession.getAgent()).thenReturn(agentIRI);
        when(mockSession.getDelegatedBy()).thenReturn(of(bseegerIRI));

        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));

        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testDefaultForNew() {
        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI5, type, ACL.Authorization),
                rdf.createTriple(authIRI5, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI5, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI6, type, ACL.Authorization),
                rdf.createTriple(authIRI6, ACL.agent, acoburnIRI),
                rdf.createTriple(authIRI6, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI6, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI8, type, ACL.Authorization),
                rdf.createTriple(authIRI8, ACL.agent, agentIRI),
                rdf.createTriple(authIRI8, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI8, ACL.default_, rootIRI),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Write)));

        when(mockSession.getAgent()).thenReturn(agentIRI);

        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertTrue(testService.canWrite(mockSession, parentIRI));
        assertTrue(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testFoafAgent() {
        when(mockSession.getAgent()).thenReturn(Trellis.AnonymousUser);
        when(mockChildResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI1, type, ACL.Authorization),
                rdf.createTriple(authIRI1, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI1, ACL.agentClass, FOAF.Agent),
                rdf.createTriple(authIRI1, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI2, type, ACL.Authorization),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI2, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI2, ACL.agent, agentIRI),
                rdf.createTriple(authIRI2, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI3, type, ACL.Authorization),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI3, ACL.agentClass, FOAF.Agent),
                rdf.createTriple(authIRI3, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI4, ACL.agent, agentIRI),
                rdf.createTriple(authIRI4, type, ACL.Authorization)));

        assertTrue(testService.canWrite(mockSession, nonexistentIRI));
        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertFalse(testService.canWrite(mockSession, rootIRI));

        assertTrue(testService.canRead(mockSession, nonexistentIRI));
        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertFalse(testService.canRead(mockSession, parentIRI));
        assertFalse(testService.canRead(mockSession, rootIRI));

        assertFalse(testService.canControl(mockSession, nonexistentIRI));
        assertFalse(testService.canControl(mockSession, resourceIRI));
        assertFalse(testService.canControl(mockSession, childIRI));
        assertFalse(testService.canControl(mockSession, parentIRI));
        assertFalse(testService.canControl(mockSession, rootIRI));

        assertFalse(testService.canAppend(mockSession, nonexistentIRI));
        assertFalse(testService.canAppend(mockSession, resourceIRI));
        assertFalse(testService.canAppend(mockSession, childIRI));
        assertFalse(testService.canAppend(mockSession, parentIRI));
        assertFalse(testService.canAppend(mockSession, rootIRI));
    }

    @Test
    public void testNotInherited() {
        when(mockParentResource.hasAcl()).thenReturn(true);
        when(mockParentResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                    rdf.createTriple(authIRI5, type, ACL.Authorization),
                    rdf.createTriple(authIRI5, ACL.accessTo, parentIRI),
                    rdf.createTriple(authIRI5, ACL.agent, agentIRI),
                    rdf.createTriple(authIRI5, ACL.mode, ACL.Read)));

        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI5, type, ACL.Authorization),
                rdf.createTriple(authIRI5, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI5, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI6, type, ACL.Authorization),
                rdf.createTriple(authIRI6, ACL.agent, acoburnIRI),
                rdf.createTriple(authIRI6, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI6, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI8, type, ACL.Authorization),
                rdf.createTriple(authIRI8, ACL.agent, agentIRI),
                rdf.createTriple(authIRI8, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI8, ACL.default_, rootIRI),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Write)));

        when(mockSession.getAgent()).thenReturn(agentIRI);

        assertTrue(testService.canWrite(mockSession, resourceIRI));
        assertTrue(testService.canWrite(mockSession, childIRI));
        assertFalse(testService.canWrite(mockSession, parentIRI));
        assertTrue(testService.canWrite(mockSession, rootIRI));
    }

    @Test
    public void testGroup() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        when(mockGroupResource.stream(eq(Trellis.PreferUserManaged))).thenAnswer(inv -> Stream.of(
                    rdf.createTriple(authIRI1, VCARD.hasMember, acoburnIRI),
                    rdf.createTriple(groupIRI, VCARD.hasMember, bseegerIRI),
                    rdf.createTriple(groupIRI, type, VCARD.Group),
                    rdf.createTriple(groupIRI, VCARD.hasMember, acoburnIRI)));

        when(mockChildResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI2, type, ACL.Authorization),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI2, ACL.agentGroup, groupIRI),
                rdf.createTriple(authIRI2, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI3, type, PROV.Activity),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI3, ACL.agentGroup, groupIRI),
                rdf.createTriple(authIRI3, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI4, ACL.agentGroup, groupIRI),
                rdf.createTriple(authIRI4, type, ACL.Authorization)));

        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI5, type, ACL.Authorization),
                rdf.createTriple(authIRI5, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI5, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI8, type, ACL.Authorization),
                rdf.createTriple(authIRI8, ACL.agentGroup, groupIRI),
                rdf.createTriple(authIRI8, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Write)));

        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }

    @Test
    public void testGroup2() {
        when(mockSession.getAgent()).thenReturn(acoburnIRI);
        when(mockGroupResource.stream(eq(Trellis.PreferUserManaged))).thenAnswer(inv -> Stream.of(
                    rdf.createTriple(authIRI1, VCARD.hasMember, acoburnIRI),
                    rdf.createTriple(groupIRI2, VCARD.hasMember, bseegerIRI),
                    rdf.createTriple(groupIRI2, type, VCARD.Group),
                    rdf.createTriple(groupIRI2, VCARD.hasMember, acoburnIRI)));

        when(mockChildResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI2, type, ACL.Authorization),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI2, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI2, ACL.agentGroup, groupIRI2),
                rdf.createTriple(authIRI2, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI3, type, PROV.Activity),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Write),
                rdf.createTriple(authIRI3, ACL.mode, ACL.Control),
                rdf.createTriple(authIRI3, ACL.agentGroup, groupIRI2),
                rdf.createTriple(authIRI3, ACL.accessTo, childIRI),

                rdf.createTriple(authIRI4, ACL.agentGroup, groupIRI2),
                rdf.createTriple(authIRI4, type, ACL.Authorization)));

        when(mockRootResource.stream(eq(Trellis.PreferAccessControl))).thenAnswer(inv -> Stream.of(
                rdf.createTriple(authIRI5, type, ACL.Authorization),
                rdf.createTriple(authIRI5, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI5, ACL.agent, bseegerIRI),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI5, ACL.mode, ACL.Append),

                rdf.createTriple(authIRI8, type, ACL.Authorization),
                rdf.createTriple(authIRI8, ACL.agentGroup, groupIRI2),
                rdf.createTriple(authIRI8, ACL.accessTo, rootIRI),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Read),
                rdf.createTriple(authIRI8, ACL.mode, ACL.Write)));

        assertTrue(testService.canRead(mockSession, resourceIRI));
        assertTrue(testService.canRead(mockSession, childIRI));
        assertTrue(testService.canRead(mockSession, parentIRI));
        assertTrue(testService.canRead(mockSession, rootIRI));
    }
}
