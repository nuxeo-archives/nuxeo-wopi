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
 *     Antoine Taillefer
 *     Thomas Roger
 */

package org.nuxeo.wopi.rest;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.Blobs;
import org.nuxeo.ecm.core.api.CloseableCoreSession;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.CoreSessionService;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentRef;
import org.nuxeo.ecm.core.api.IdRef;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.blobholder.BlobHolder;
import org.nuxeo.ecm.core.api.repository.RepositoryManager;
import org.nuxeo.ecm.core.api.security.SecurityConstants;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.kv.KeyValueService;
import org.nuxeo.runtime.kv.KeyValueStore;

/**
 * Implementation of the Files endpoint.
 * <p>
 * See <a href="https://wopirest.readthedocs.io/en/latest/endpoints.html#files-endpoint"></a>.
 *
 * @since 10.3
 */
@Path("/wopi/files/{fileId}")
public class FilesResource {

    @Context
    protected HttpServletRequest request;

    @Context
    protected HttpServletResponse response;

    /**
     * Implements the CheckFileInfo operation.
     * <p>
     * See <a href="https://wopirest.readthedocs.io/en/latest/files/CheckFileInfo.html"></a>.
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Object checkFileInfo(@PathParam("fileId") String fileId) {
        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            FileInfo.Builder builder = FileInfo.builder();
            addRequiredProperties(builder, doc, blob, principal);
            addHostCapabilitiesProperties(builder);
            addUserMetadataProperties(builder, principal);
            addUserPermissionsProperties(builder, session, doc);
            addFileURLProperties(builder);
            addBreadcrumbProperties(builder);
            return builder.build();
        }
    }

    /**
     * Implements the GetFile operation.
     * <p>
     * See <a href="https://wopi.readthedocs.io/projects/wopirest/en/latest/files/GetFile.html"></a>.
     */
    @GET
    @Path("contents")
    public Object getFile(@PathParam("fileId") String fileId,
            @HeaderParam("X-WOPI-MaxExpectedSize") String maxExpectedSizeHeader) {
        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            int maxExpectedSize = getMaxExpectedSize(maxExpectedSizeHeader);
            if (blob.getLength() > maxExpectedSize) {
                return Response.status(Response.Status.PRECONDITION_FAILED).build();
            }

            response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
            return blob;
        }
    }

    @POST
    public Object doPost(@PathParam("fileId") String fileId, @HeaderParam("X-WOPI-Override") String override,
            @HeaderParam("X-WOPI-Lock") String lock, @HeaderParam("X-WOPI-OldLock") String oldLock) {
        if (StringUtils.isBlank(override)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        switch (override) {
        case "LOCK":
            return lock(fileId, lock, oldLock);
        case "UNLOCK":
            return unlock(fileId, lock);
        case "REFRESH_LOCK":
            return refreshLock(fileId, lock);
        case "DELETE":
                return deleteFile(fileId);
        default:
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    protected Object lock(String fileId, String lock, String oldLock) {
        if (StringUtils.isBlank(lock)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            KeyValueService service = Framework.getService(KeyValueService.class);
            KeyValueStore store = service.getKeyValueStore("wopi-locks");
            boolean isLocked = doc.isLocked();
            if (!isLocked) {
                if (!StringUtils.isBlank(oldLock)) {
                    // cannot unlock and relock
                    response.addHeader("X-WOPI-Lock", "");
                    return Response.status(Response.Status.CONFLICT).build();
                }

                if (!session.hasPermission(doc.getRef(), SecurityConstants.WRITE_PROPERTIES)) {
                    // cannot lock
                    return Response.status(Response.Status.CONFLICT).build();
                }
                // lock
                doc.setLock();
                store.put(doc.getId(), lock, 30 * 60 * 1000); // TODO multi repository - compute a key?
                response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
                return Response.ok().build();
            }

            String currentLock = store.getString(doc.getId());
            if (currentLock == null) {
                // locked by Nuxeo
                return Response.status(Response.Status.CONFLICT).build();
            }

            if (StringUtils.isBlank(oldLock)) {
                if (lock.equals(currentLock)) {
                    // refresh lock
                    store.setTTL(doc.getId(), 30 * 60 * 1000);
                    response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
                    return Response.ok().build();
                }
            } else {
                if (oldLock.equals(currentLock)) {
                    store.put(doc.getId(), lock, 30 * 60 * 1000);
                    return Response.ok().build();
                }
            }

            // locked by another WOPI client
            response.addHeader("X-WOPI-Lock", currentLock);
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    protected Object unlockOrRefresh(String fileId, String lock, boolean unlock) {
        if (StringUtils.isBlank(lock)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            KeyValueService service = Framework.getService(KeyValueService.class);
            KeyValueStore store = service.getKeyValueStore("wopi-locks");
            boolean isLocked = doc.isLocked();
            if (!isLocked) {
                // not locked
                response.addHeader("X-WOPI-Lock", "");
                return Response.status(Response.Status.CONFLICT).build();
            }

            String currentLock = store.getString(doc.getId());
            if (currentLock == null) {
                // locked by Nuxeo
                return Response.status(Response.Status.CONFLICT).build();
            }

            if (lock.equals(currentLock)) {
                if (!session.hasPermission(doc.getRef(), SecurityConstants.WRITE_PROPERTIES)) {
                    // cannot unlock
                    return Response.status(Response.Status.CONFLICT).build();
                }
                if (unlock) {
                    // unlock
                    doc.removeLock();
                    store.put(doc.getId(), (String) null);
                    response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
                } else {
                    // refresh lock
                    store.setTTL(doc.getId(), 30 * 60 * 1000);
                }
                return Response.ok().build();
            }

            // locked by another WOPI client
            response.addHeader("X-WOPI-Lock", currentLock);
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    /**
     * Implements the DeleteFile operation.
     * <p>
     * See <a href="https://wopi.readthedocs.io/projects/wopirest/en/latest/files/DeleteFile.html"></a>.
     */
    public Object deleteFile(String fileId) {
        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            KeyValueService service = Framework.getService(KeyValueService.class);
            KeyValueStore store = service.getKeyValueStore("wopi-locks");
            if (doc.isLocked()) {
                String currentLock = store.getString(doc.getId());
                if (currentLock != null) {
                    response.addHeader("X-WOPI-Lock", currentLock);
                }
                return Response.status(Response.Status.CONFLICT).build();
            }

            if (!session.hasPermission(doc.getRef(), SecurityConstants.REMOVE)) {
                // cannot delete
                return Response.status(Response.Status.CONFLICT).build();
            }

            session.removeDocument(ref);
            return Response.ok().build();
        }
    }

    @POST
    @Path("contents")
    public Object doPostContents(@PathParam("fileId") String fileId, @HeaderParam("X-WOPI-Override") String override,
            @HeaderParam("X-WOPI-Lock") String lock) throws IOException {
        if (StringUtils.isBlank(override)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        switch (override) {
        case "PUT":
            return putFile(fileId, lock);
        default:
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    /**
     * Implements the PutFile operation.
     * <p>
     * See <a href="https://wopi.readthedocs.io/projects/wopirest/en/latest/files/PutFile.html"></a>.
     */
    public Object putFile(String fileId, String lock) throws IOException {
        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = createCoreSession(principal)) {
            DocumentRef ref = new IdRef(fileId);
            if (!session.exists(ref)) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            if (!doc.isLocked()) {
                if (blob.getLength() == 0) {
                    if (!session.hasPermission(doc.getRef(), SecurityConstants.WRITE_PROPERTIES)) {
                        // cannot update blob
                        return Response.status(Response.Status.CONFLICT).build();
                    }
                    try (InputStream is = request.getInputStream()) {
                        Blob newBlob = Blobs.createBlob(is);
                        newBlob.setFilename(blob.getFilename());
                        newBlob.setMimeType(blob.getMimeType());
                        BlobHolder bh = doc.getAdapter(BlobHolder.class);
                        bh.setBlob(newBlob);
                        doc.putContextData("source", "wopi");
                        doc = session.saveDocument(doc);
                        response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
                        return Response.ok().build();
                    }
                }
                response.addHeader("X-WOPI-Lock", "");
                return Response.status(Response.Status.CONFLICT).build();
            }

            KeyValueService service = Framework.getService(KeyValueService.class);
            KeyValueStore store = service.getKeyValueStore("wopi-locks");
            String currentLock = store.getString(doc.getId());
            if (currentLock == null) {
                // locked by Nuxeo
                return Response.status(Response.Status.CONFLICT).build();
            }

            if (lock.equals(currentLock)) {
                if (!session.hasPermission(doc.getRef(), SecurityConstants.WRITE_PROPERTIES)) {
                    // cannot update blob
                    return Response.status(Response.Status.CONFLICT).build();
                }
                try (InputStream is = request.getInputStream()) {
                    Blob newBlob = Blobs.createBlob(is);
                    newBlob.setFilename(blob.getFilename());
                    newBlob.setMimeType(blob.getMimeType());
                    BlobHolder bh = doc.getAdapter(BlobHolder.class);
                    bh.setBlob(newBlob);
                    doc.putContextData("source", "wopi");
                    doc = session.saveDocument(doc);
                    response.addHeader("X-WOPI-ItemVersion", doc.getVersionLabel());
                    return Response.ok().build();
                }
            }

            // locked by another WOPI client
            response.addHeader("X-WOPI-Lock", currentLock);
            return Response.status(Response.Status.CONFLICT).build();
        }
    }

    protected Object unlock(String fileId, String lock) {
        return unlockOrRefresh(fileId, lock, true);
    }

    protected Object refreshLock(String fileId, String lock) {
        return unlockOrRefresh(fileId, lock, false);
    }

    protected int getMaxExpectedSize(String maxExpectedSizeHeader) {
        if (!StringUtils.isBlank(maxExpectedSizeHeader)) {
            try {
                return Integer.parseInt(maxExpectedSizeHeader, 10);
            } catch (NumberFormatException e) {
                // do nothing
            }
        }
        return Integer.MAX_VALUE;
    }

    protected FileInfo.Builder addRequiredProperties(FileInfo.Builder builder, DocumentModel doc, Blob blob,
            NuxeoPrincipal principal) {
        return builder.baseFileName(blob.getFilename()) // TODO or dc:title?
                      .ownerId((String) doc.getPropertyValue("dc:creator"))
                      .size(blob.getLength())
                      .userId(principal.getName())
                      .version(doc.getVersionLabel());
    }

    protected FileInfo.Builder addHostCapabilitiesProperties(FileInfo.Builder builder) {
        return builder.supportsLocks(true).supportsUpdate(true).supportsDeleteFile(true);
    }

    protected FileInfo.Builder addUserMetadataProperties(FileInfo.Builder builder, NuxeoPrincipal principal) {
        return builder.isAnonymousUser(principal.isAnonymous()).userFriendlyName(principalFullName(principal));
    }

    protected FileInfo.Builder addUserPermissionsProperties(FileInfo.Builder builder, CoreSession session,
            DocumentModel doc) {
        boolean hasWriteProperties = session.hasPermission(doc.getRef(), SecurityConstants.WRITE_PROPERTIES);
        return builder.readOnly(!hasWriteProperties).userCanRename(hasWriteProperties).userCanWrite(hasWriteProperties);
    }

    protected FileInfo.Builder addFileURLProperties(FileInfo.Builder builder) {
        return builder;
    }

    protected FileInfo.Builder addBreadcrumbProperties(FileInfo.Builder builder) {
        return builder;
    }

    protected Blob getMainBlob(DocumentModel doc) {
        BlobHolder bh = doc.getAdapter(BlobHolder.class);
        // TODO check cloud services blob provider?
        Blob blob;
        if (bh == null || (blob = bh.getBlob()) == null) {
            return null;
        }
        return blob;
    }

    protected static CloseableCoreSession createCoreSession(NuxeoPrincipal principal) {
        // TODO handle multi repository
        String repoName = Framework.getService(RepositoryManager.class).getDefaultRepositoryName();
        return Framework.getService(CoreSessionService.class).createCoreSession(repoName, principal);
    }

    // copied from org.nuxeo.ecm.platform.ui.web.tag.fn.Functions which lives in nuxeo-platform-ui-web
    public static String principalFullName(NuxeoPrincipal principal) {
        String first = principal.getFirstName();
        String last = principal.getLastName();
        return userDisplayName(principal.getName(), first, last);
    }

    public static String userDisplayName(String id, String first, String last) {
        if (first == null || first.length() == 0) {
            if (last == null || last.length() == 0) {
                return id;
            } else {
                return last;
            }
        } else {
            if (last == null || last.length() == 0) {
                return first;
            } else {
                return first + ' ' + last;
            }
        }
    }
}
