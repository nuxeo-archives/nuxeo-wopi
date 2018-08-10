/*
 * (C) Copyright 2018 Nuxeo (http://nuxeo.com/) and others.
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
 *
 * Contributors:
 *     Thomas Roger
 */

package org.nuxeo.wopi.jaxrs;

import static org.nuxeo.wopi.Constants.FILE_CONTENT_PROPERTY;

import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentRef;
import org.nuxeo.ecm.core.api.IdRef;
import org.nuxeo.ecm.webengine.model.WebObject;
import org.nuxeo.ecm.webengine.model.impl.ModuleRoot;
import org.nuxeo.wopi.exception.NotFoundException;

/**
 * @since 10.3
 */
@Path("/wopi")
@WebObject(type = "wopi")
public class WOPIRoot extends ModuleRoot {

    @Path("/files/{fileId}")
    public Object filesResource(@PathParam("fileId") String fileId) {
        // TODO handle multi repository
        CoreSession session = getContext().getCoreSession();
        DocumentModel doc = getDocument(session, fileId);
        Blob blob = getMainBlob(doc);
        return newObject("wopiFiles", session, doc, blob);
    }

    protected DocumentModel getDocument(CoreSession session, String fileId) {
        DocumentRef ref = new IdRef(fileId);
        if (!session.exists(ref)) {
            throw new NotFoundException();
        }
        return session.getDocument(ref);
    }

    protected Blob getMainBlob(DocumentModel doc) {
        // TODO check cloud services blob provider?
        Blob blob = (Blob) doc.getPropertyValue(FILE_CONTENT_PROPERTY);
        if (blob == null) {
            throw new NotFoundException();
        }
        return blob;
    }

}
