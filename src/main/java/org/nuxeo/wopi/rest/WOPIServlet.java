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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.CloseableCoreSession;
import org.nuxeo.ecm.core.api.CoreSessionService;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentRef;
import org.nuxeo.ecm.core.api.IdRef;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.blobholder.BlobHolder;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.ecm.tokenauth.service.TokenAuthenticationService;
import org.nuxeo.runtime.api.Framework;

/**
 * @since 10.3
 */
public class WOPIServlet extends HttpServlet {

    public static final String WORD_VIEW_URL = "https://word-view.officeapps-df.live.com/wv/wordviewerframe.aspx?";

    public static final String WORD_EDIT_URL = "https://word-edit.officeapps-df.live.com/we/wordeditorframe.aspx?";

    public static final String EXCEL_VIEW_URL = "https://excel.officeapps-df.live.com/x/_layouts/xlviewerinternal.aspx?";

    public static final String EXCEL_EDIT_URL = EXCEL_VIEW_URL + "edit=1&";

    public static final String POWERPOINT_VIEW_URL = "https://powerpoint.officeapps-df.live.com/p/PowerPointFrame.aspx?PowerPointView=ReadingView&";

    public static final String POWERPOINT_EDIT_URL = "https://powerpoint.officeapps-df.live.com/p/PowerPointFrame.aspx?PowerPointView=EditView&";

    public static final String WOPITEST_VIEW_URL = "https://onenote.officeapps-df.live.com/hosting/WopiTestFrame.aspx?";

    public static final Map<Pair<String, String>, String> ACTIONS_TO_URLS = new HashMap<>();

    static {
        ACTIONS_TO_URLS.put(Pair.of("view", "doc"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "docm"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "docx"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "dot"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "dotm"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "docx"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "odt"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "rtf"), WORD_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "docm"), WORD_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "docx"), WORD_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "odt"), WORD_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "csv"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "ods"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "xls"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "xlsb"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "xslm"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "xslx"), EXCEL_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "ods"), EXCEL_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "xlsb"), EXCEL_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "xslm"), EXCEL_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "xslx"), EXCEL_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "odp"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "pot"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "potm"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "potx"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "pps"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "ppsm"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "ppsx"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "ppt"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "pptm"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("view", "pptx"), POWERPOINT_VIEW_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "odp"), POWERPOINT_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "ppsx"), POWERPOINT_EDIT_URL);
        ACTIONS_TO_URLS.put(Pair.of("edit", "pptx"), POWERPOINT_EDIT_URL);
        // for testing
        ACTIONS_TO_URLS.put(Pair.of("view", "wopitest"), WOPITEST_VIEW_URL);
    }

    public static final String WOPI_JSP = "/wopi.jsp";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String requestURI;
        try {
            requestURI = new URI(request.getRequestURI()).getPath();
        } catch (URISyntaxException e) {
            requestURI = request.getRequestURI();
        }
        // remove context
        String context = VirtualHostHelper.getContextPath(request) + "/";
        if (!requestURI.startsWith(context)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid URL syntax");
            return;
        }
        String path = requestURI.substring(context.length());
        // wopi/file/default/qwrqw
        String[] parts = path.split("/");
        int length = parts.length;
        if (length < 4) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid path: " + path);
            return;
        }

        String action = parts[1];
        String repository = parts[2];
        String docId = parts[3];
        NuxeoPrincipal principal = (NuxeoPrincipal) request.getUserPrincipal();
        try (CloseableCoreSession session = Framework.getService(CoreSessionService.class).createCoreSession(repository,
                principal)) {
            DocumentRef ref = new IdRef(docId);
            if (!session.exists(ref)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
                return;
            }

            DocumentModel doc = session.getDocument(ref);
            Blob blob = getMainBlob(doc);
            if (blob == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "No blob on document");
                return;
            }

            String extension = FilenameUtils.getExtension(blob.getFilename());
            String url = ACTIONS_TO_URLS.get(Pair.of(action, extension));
            if (url == null) {
                // TODO http code?
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Cannot open file with Office Online");
                return;
            }

            TokenAuthenticationService tokenAuthenticationService = Framework.getService(
                    TokenAuthenticationService.class);
            String token = tokenAuthenticationService.acquireToken(principal.getName(), "wopi", "device", null, "rw");
            request.setAttribute("accessToken", token);
            String baseURL = VirtualHostHelper.getBaseURL(request);
            String wopiSrc = String.format("%ssite/wopi/files/%s", baseURL, docId);
            request.setAttribute("formURL", url + "WOPISrc=" + wopiSrc);
            RequestDispatcher requestDispatcher = request.getRequestDispatcher(WOPI_JSP);
            requestDispatcher.forward(request, response);
        }
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
}
