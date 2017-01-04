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

import java.util.Optional;
import java.util.stream.Stream;

import edu.amherst.acdc.trellis.spi.AccessControlService;
import edu.amherst.acdc.trellis.spi.Authorization;
import edu.amherst.acdc.trellis.spi.Session;
import org.apache.commons.rdf.api.IRI;

/**
 *
 * @author acoburn
 */
public class WebACService implements AccessControlService {

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
        return Optional.empty();
    }

    @Override
    public Optional<IRI> findAncestorWithAccessControl(final IRI identifier) {
        return Optional.empty();
    }

    @Override
    public Stream<Authorization> getAuthorizations(final IRI identifier) {
        return Stream.empty();
    }
}
