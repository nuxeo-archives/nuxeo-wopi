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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import javax.inject.Inject;

import org.json.JSONException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.nuxeo.common.utils.FileUtils;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.Blobs;
import org.nuxeo.ecm.core.api.CloseableCoreSession;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.blobholder.BlobHolder;
import org.nuxeo.ecm.core.api.security.ACE;
import org.nuxeo.ecm.core.api.security.ACL;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.platform.test.PlatformFeature;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.restapi.test.RestServerFeature;
import org.nuxeo.ecm.tokenauth.service.TokenAuthenticationService;
import org.nuxeo.jaxrs.test.CloseableClientResponse;
import org.nuxeo.jaxrs.test.JerseyClientHelper;
import org.nuxeo.runtime.kv.KeyValueService;
import org.nuxeo.runtime.kv.KeyValueStore;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.ServletContainer;
import org.nuxeo.runtime.test.runner.TransactionalFeature;
import org.skyscreamer.jsonassert.JSONAssert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;

/**
 * Tests the {@link FilesResource} WOPI endpoint.
 *
 * @since 10.3
 */
@RunWith(FeaturesRunner.class)
@Features({ PlatformFeature.class, RestServerFeature.class })
@Deploy("org.nuxeo.ecm.platform.login.token")
@Deploy("org.nuxeo.wopi.rest.api")
@ServletContainer(port = 18090)
public class TestFilesResource {

    public static final String BASE_URL = "http://localhost:18090/wopi/files";

    @Inject
    protected UserManager userManager;

    @Inject
    protected CoreSession session;

    @Inject
    protected CoreFeature coreFeature;

    @Inject
    protected KeyValueService keyValueService;

    @Inject
    protected TokenAuthenticationService tokenAuthenticationService;

    @Inject
    protected TransactionalFeature transactionalFeature;

    protected Client client;

    protected String joeToken;

    protected String johnToken;

    protected DocumentModel blobDoc;

    protected DocumentModel zeroLengthBlobDoc;

    protected DocumentModel hugeBlobDoc;

    protected DocumentModel noBlobDoc;

    ObjectMapper mapper;

    @Before
    public void setUp() throws IOException {
        mapper = new ObjectMapper();

        createUsers();

        createDocuments();

        // initialize REST API clients
        joeToken = tokenAuthenticationService.acquireToken("joe", "wopi", "device", null, "rw");
        johnToken = tokenAuthenticationService.acquireToken("john", "wopi", "device", null, "rw");
        client = JerseyClientHelper.clientBuilder().build();

        // make sure everything is committed
        transactionalFeature.nextTransaction();
    }

    protected void createUsers() {
        DocumentModel joe = userManager.getBareUserModel();
        joe.setPropertyValue("user:username", "joe");
        joe.setPropertyValue("user:password", "joe");
        joe.setPropertyValue("user:firstName", "Joe");
        joe.setPropertyValue("user:lastName", "Jackson");
        userManager.createUser(joe);

        DocumentModel john = userManager.getBareUserModel();
        john.setPropertyValue("user:username", "john");
        john.setPropertyValue("user:password", "john");
        john.setPropertyValue("user:firstName", "John");
        john.setPropertyValue("user:lastName", "Doe");
        userManager.createUser(john);
    }

    protected void createDocuments() throws IOException {
        DocumentModel folder = session.createDocumentModel("/", "wopi", "Folder");
        folder = session.createDocument(folder);
        ACP acp = folder.getACP();
        ACL localACL = acp.getOrCreateACL(ACL.LOCAL_ACL);
        localACL.add(new ACE("john", "ReadWrite", true));
        localACL.add(new ACE("joe", "Read", true));
        folder.setACP(acp, true);

        try (CloseableCoreSession johnSession = coreFeature.openCoreSession("john")) {
            blobDoc = johnSession.createDocumentModel("/wopi", "blobDoc", "File");
            Blob blob = Blobs.createBlob(FileUtils.getResourceFileFromContext("test-file.txt"));
            blobDoc.setPropertyValue("file:content", (Serializable) blob);
            blobDoc = johnSession.createDocument(blobDoc);

            zeroLengthBlobDoc = johnSession.createDocumentModel("/wopi", "zeroLengthBlobDoc", "File");
            Blob zeroLengthBlob = Blobs.createBlob("");
            zeroLengthBlob.setFilename("zero-length-blob");
            zeroLengthBlobDoc.setPropertyValue("file:content", (Serializable) zeroLengthBlob);
            zeroLengthBlobDoc = johnSession.createDocument(zeroLengthBlobDoc);

            hugeBlobDoc = johnSession.createDocumentModel("/wopi", "hugeBlobDoc", "File");
            Blob hugeBlob = mock(Blob.class, withSettings().serializable());
            Mockito.when(hugeBlob.getLength()).thenReturn(Long.MAX_VALUE);
            Mockito.when(hugeBlob.getStream()).thenReturn(new ByteArrayInputStream(new byte[] {}));
            Mockito.when(hugeBlob.getFilename()).thenReturn("hugeBlobFilename");
            hugeBlobDoc.setPropertyValue("file:content", (Serializable) hugeBlob);
            hugeBlobDoc = johnSession.createDocument(hugeBlobDoc);

            noBlobDoc = johnSession.createDocumentModel("/wopi", "noBlobDoc", "File");
            noBlobDoc = johnSession.createDocument(noBlobDoc);
        }
    }

    @After
    public void tearDown() {
        Stream.of("john", "joe").forEach(userManager::deleteUser);
        Stream.of(johnToken, joeToken).forEach(tokenAuthenticationService::revokeToken);
        client.destroy();
    }

    @Test
    public void testCheckFileInfo() throws IOException, JSONException {
        // fail - 404
        checkGetNotFound();

        // success - john has write access
        try (CloseableClientResponse response = get(johnToken, blobDoc.getId())) {
            checkJSONResponse(response, "json/CheckFileInfo-john-write.json");
        }

        // success - joe has read access
        try (CloseableClientResponse response = get(joeToken, blobDoc.getId())) {
            checkJSONResponse(response, "json/CheckFileInfo-joe-read.json");
        }
    }

    @Test
    public void testGetFile() throws IOException {
        // fail - 404
        checkGetNotFound("contents");

        // fail - 412 - blob size exceeding Integer.MAX_VALUE
        try (CloseableClientResponse response = get(joeToken, hugeBlobDoc.getId(), "contents")) {
            assertEquals(412, response.getStatus());
        }

        // fail - 412 - blob size exceeding X-WOPI-MaxExpectedSize header
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-MaxExpectedSize", "1");
        try (CloseableClientResponse response = get(joeToken, headers, blobDoc.getId(), "contents")) {
            assertEquals(412, response.getStatus());
        }

        Blob expectedBlob = Blobs.createBlob(FileUtils.getResourceFileFromContext("test-file.txt"));
        // success - bad header
        headers.put("X-WOPI-MaxExpectedSize", "foo");
        try (CloseableClientResponse response = get(joeToken, headers, blobDoc.getId(), "contents")) {
            assertEquals(200, response.getStatus());
            Blob actualBlob = Blobs.createBlob(response.getEntityInputStream());
            assertEquals(expectedBlob.getString(), actualBlob.getString());
        }

        // success - no header
        try (CloseableClientResponse response = get(joeToken, blobDoc.getId(), "contents")) {
            assertEquals(200, response.getStatus());
            Blob actualBlob = Blobs.createBlob(response.getEntityInputStream());
            assertEquals(expectedBlob.getString(), actualBlob.getString());
        }
    }

    @Test
    public void testLock() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "LOCK");

        // fail - 404
        checkPostNotFound(headers);

        // fail - 400 - no X-WOPI-Lock header
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 400 - empty header
        headers.put("X-WOPI-Lock", "");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 409 - no write permission, cannot lock
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(joeToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
        }

        // success - 200 - can lock
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String itemVersion = response.getHeaders().getFirst("X-WOPI-ItemVersion");
            assertEquals("0.0", itemVersion);
        }

        // success - 200 - refresh lock
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String itemVersion = response.getHeaders().getFirst("X-WOPI-ItemVersion");
            assertEquals("0.0", itemVersion);
        }

        // fail - 409 - locked by another client
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(hugeBlobDoc.getRef()).isLocked());
        }
    }

    @Test
    public void testUnlock() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "UNLOCK");

        // fail - 404
        checkPostNotFound(headers);

        // fail - 400 - no X-WOPI-Lock header
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 400 - empty header
        headers.put("X-WOPI-Lock", "");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 409 - not locked
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("", lock);
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(hugeBlobDoc.getRef()).isLocked());
        }

        // lock document from WOPI client
        headers.put("X-WOPI-Override", "LOCK");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - no write permission, cannot unlock
        headers.put("X-WOPI-Override", "UNLOCK");
        try (CloseableClientResponse response = post(joeToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - lock mismatch
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
        }

        // success - 200 - can unlock
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertFalse(session.getDocument(blobDoc.getRef()).isLocked());
            String itemVersion = response.getHeaders().getFirst("X-WOPI-ItemVersion");
            assertEquals("0.0", itemVersion);
        }
    }

    @Test
    public void testRefresh() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "REFRESH_LOCK");

        // fail - 404
        checkPostNotFound(headers);

        // fail - 400 - no X-WOPI-Lock header
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 400 - empty header
        headers.put("X-WOPI-Lock", "");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 409 - not locked
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("", lock);
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(hugeBlobDoc.getRef()).isLocked());
        }

        // lock document from WOPI client
        headers.put("X-WOPI-Override", "LOCK");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - no write permission, cannot unlock
        headers.put("X-WOPI-Override", "REFRESH_LOCK");
        try (CloseableClientResponse response = post(joeToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - lock mismatch
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
        }

        // success - 200 - can refresh lock
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }
    }

    @Test
    public void testUnlockAndRelock() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "LOCK");

        // fail - 404
        checkPostNotFound(headers);

        // fail - 400 - no X-WOPI-Lock header
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 400 - empty header
        headers.put("X-WOPI-Lock", "");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(400, response.getStatus());
        }

        // fail - 409- cannot unlock and relock unlocked document
        headers.put("X-WOPI-Lock", "foo");
        headers.put("X-WOPI-OldLock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertFalse(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("", lock);
        }

        // lock document from WOPI client
        headers.remove("X-WOPI-OldLock");
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // success - 200 - lock and relock
        headers.put("X-WOPI-Lock", "bar");
        headers.put("X-WOPI-OldLock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            KeyValueStore store = keyValueService.getKeyValueStore("wopi-locks");
            assertEquals("bar", store.getString(blobDoc.getId()));
        }

        // fail - 409 - locked by another client
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("bar", lock);
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(hugeBlobDoc.getRef()).isLocked());
        }
    }

    @Test
    public void testRenameFile() throws IOException, JSONException {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "RENAME_FILE");

        checkPostNotFound(headers, "contents");

        // fail - 409 - joe has no write permission
        try (CloseableClientResponse response = post(joeToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
        }

        // success - 200 - blob renamed
        headers.put("X-WOPI-RequestedName", "renamed-test-file.txt");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            checkJSONResponse(response, "json/RenameFile.json");
            transactionalFeature.nextTransaction();
            Blob renamedBlob = session.getDocument(blobDoc.getRef()).getAdapter(BlobHolder.class).getBlob();
            assertNotNull(renamedBlob);
            assertEquals("renamed-test-file.txt", renamedBlob.getFilename());
        }

        // lock document from WOPI client
        headers.put("X-WOPI-Override", "LOCK");
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - joe has no write permission
        headers.put("X-WOPI-Override", "RENAME_FILE");
        headers.put("X-WOPI-RequestedName", "renamed-wopi-locked-test-file.txt");
        try (CloseableClientResponse response = post(joeToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
        }

        // success - 200 - blob renamed
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            checkJSONResponse(response, "json/RenameFile-wopiLocked.json");
            transactionalFeature.nextTransaction();
            Blob renamedBlob = session.getDocument(blobDoc.getRef()).getAdapter(BlobHolder.class).getBlob();
            assertNotNull(renamedBlob);
            assertEquals("renamed-wopi-locked-test-file.txt", renamedBlob.getFilename());
        }

        // fail - 409 - locked by another client
        headers.put("X-WOPI-Lock", "bar");
        headers.put("X-WOPI-RequestedName", "renamed-wopi-locked-other-client-test-file.txt");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
            transactionalFeature.nextTransaction();
            DocumentModel doc = session.getDocument(blobDoc.getRef());
            assertTrue(doc.isLocked());
            Blob blob = doc.getAdapter(BlobHolder.class).getBlob();
            assertNotNull(blob);
            assertEquals("renamed-wopi-locked-test-file.txt", blob.getFilename());
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        headers.remove("X-WOPI-Lock");
        headers.put("X-WOPI-RequestedName", "renamed-wopi-locked-nuxeo-test-file.txt");
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            DocumentModel doc = session.getDocument(hugeBlobDoc.getRef());
            assertTrue(doc.isLocked());
            Blob blob = doc.getAdapter(BlobHolder.class).getBlob();
            assertNotNull(blob);
            assertEquals("hugeBlobFilename", blob.getFilename());
        }
    }

    @Test
    public void testDeleteFile() {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "DELETE");

        checkPostNotFound(headers);

        // success - 200 - delete file
        try (CloseableClientResponse response = post(johnToken, headers, zeroLengthBlobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertFalse(session.exists(zeroLengthBlobDoc.getRef()));
        }

        // lock document from WOPI client
        headers.put("X-WOPI-Override", "LOCK");
        headers.put("X-WOPI-Lock", "foo");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - cannot delete, locked by another client
        headers.put("X-WOPI-Override", "DELETE");
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            assertTrue(session.exists(blobDoc.getRef()));
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
        }

        // fail - 409 - cannot delete, locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, headers, hugeBlobDoc.getId())) {
            assertEquals(409, response.getStatus());
            assertTrue(session.exists(hugeBlobDoc.getRef()));
        }
    }

    @Test
    public void testPutFile() throws IOException {
        String data = "new content";
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WOPI-Override", "PUT");

        checkPostNotFound(headers, "contents");

        // fail - 409 - joe has no write permission
        try (CloseableClientResponse response = post(joeToken, data, headers, zeroLengthBlobDoc.getId(), "contents")) {
            assertEquals(409, response.getStatus());
        }

        // success - 200 - blob updated
        try (CloseableClientResponse response = post(johnToken, data, headers, zeroLengthBlobDoc.getId(), "contents")) {
            assertEquals(200, response.getStatus());
            String itemVersion = response.getHeaders().getFirst("X-WOPI-ItemVersion");
            assertEquals("0.1", itemVersion); // TODO weird?
            transactionalFeature.nextTransaction();
            Blob updatedBlob = session.getDocument(zeroLengthBlobDoc.getRef()).getAdapter(BlobHolder.class).getBlob();
            assertNotNull(updatedBlob);
            assertEquals("new content", updatedBlob.getString());
            assertEquals("zero-length-blob", updatedBlob.getFilename());
        }

        // fail - 409 - not locked and blob present
        try (CloseableClientResponse response = post(johnToken, data, headers, blobDoc.getId(), "contents")) {
            assertEquals(409, response.getStatus());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("", lock);
        }

        // lock document from WOPI client
        headers.put("X-WOPI-Lock", "foo");
        headers.put("X-WOPI-Override", "LOCK");
        try (CloseableClientResponse response = post(johnToken, headers, blobDoc.getId())) {
            assertEquals(200, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
        }

        // fail - 409 - joe has no write permission
        headers.put("X-WOPI-Override", "PUT");
        try (CloseableClientResponse response = post(joeToken, data, headers, blobDoc.getId(), "contents")) {
            assertEquals(409, response.getStatus());
        }

        // success - 200 - blob updated
        try (CloseableClientResponse response = post(johnToken, data, headers, blobDoc.getId(), "contents")) {
            assertEquals(200, response.getStatus());
            String itemVersion = response.getHeaders().getFirst("X-WOPI-ItemVersion");
            assertEquals("0.1", itemVersion); // TODO weird?
            transactionalFeature.nextTransaction();
            Blob updatedBlob = session.getDocument(blobDoc.getRef()).getAdapter(BlobHolder.class).getBlob();
            assertNotNull(updatedBlob);
            assertEquals("new content", updatedBlob.getString());
            assertEquals("test-file.txt", updatedBlob.getFilename());
        }

        // fail - 409 - locked by another client
        headers.put("X-WOPI-Lock", "bar");
        try (CloseableClientResponse response = post(johnToken, data, headers, blobDoc.getId(), "contents")) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(blobDoc.getRef()).isLocked());
            String lock = response.getHeaders().getFirst("X-WOPI-Lock");
            assertEquals("foo", lock);
        }

        // fail - 409 - locked by Nuxeo
        session.getDocument(hugeBlobDoc.getRef()).setLock();
        transactionalFeature.nextTransaction();
        try (CloseableClientResponse response = post(johnToken, data, headers, hugeBlobDoc.getId(), "contents")) {
            assertEquals(409, response.getStatus());
            assertTrue(session.getDocument(hugeBlobDoc.getRef()).isLocked());
        }
    }

    protected void checkPostNotFound(Map<String, String> headers) {
        checkPostNotFound(headers, "");
    }

    protected void checkPostNotFound(Map<String, String> headers, String additionalPath) {
        // not found
        try (CloseableClientResponse response = get(johnToken, headers, "foo", additionalPath)) {
            assertEquals(404, response.getStatus());
        }

        // no blob
        try (CloseableClientResponse response = get(johnToken, headers, noBlobDoc.getId(), additionalPath)) {
            assertEquals(404, response.getStatus());
        }
    }

    protected void checkGetNotFound() {
        checkGetNotFound("");
    }

    protected void checkGetNotFound(String additionalPath) {
        // not found
        try (CloseableClientResponse response = get(johnToken, "foo", additionalPath)) {
            assertEquals(404, response.getStatus());
        }

        // no blob
        try (CloseableClientResponse response = get(johnToken, noBlobDoc.getId(), additionalPath)) {
            assertEquals(404, response.getStatus());
        }
    }

    protected void checkJSONResponse(ClientResponse response, String expectedJSONFile)
            throws IOException, JSONException {
        assertEquals(200, response.getStatus());
        String json = response.getEntity(String.class);
        File file = FileUtils.getResourceFileFromContext(expectedJSONFile);
        String expected = org.apache.commons.io.FileUtils.readFileToString(file, UTF_8);
        JSONAssert.assertEquals(expected, json, true);
    }

    protected CloseableClientResponse get(String token, String... path) {
        return get(token, null, path);
    }

    protected CloseableClientResponse get(String token, Map<String, String> headers, String... path) {
        WebResource wr = client.resource(BASE_URL).path(String.join("/", path)).queryParam("access_token", token);
        ;
        WebResource.Builder builder = wr.getRequestBuilder();
        if (headers != null) {
            headers.forEach(builder::header);
        }
        return CloseableClientResponse.of(builder.get(ClientResponse.class));
    }

    protected CloseableClientResponse post(String token, Map<String, String> headers, String... path) {
        return post(token, null, headers, path);
    }

    protected CloseableClientResponse post(String token, String data, Map<String, String> headers, String... path) {
        WebResource wr = client.resource(BASE_URL).path(String.join("/", path)).queryParam("access_token", token);
        WebResource.Builder builder = wr.getRequestBuilder();
        if (headers != null) {
            headers.forEach(builder::header);
        }
        return CloseableClientResponse.of(
                data != null ? builder.post(ClientResponse.class, data) : builder.post(ClientResponse.class));
    }
}
