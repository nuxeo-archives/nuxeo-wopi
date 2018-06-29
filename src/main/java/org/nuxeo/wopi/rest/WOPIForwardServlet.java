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

import org.nuxeo.ecm.core.api.NuxeoException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @since 10.3
 */
public class WOPIForwardServlet extends HttpServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String toReplace = req.getContextPath() + "/wopi";
        String newPath = req.getRequestURI();
        if (newPath.startsWith(toReplace)) {
            newPath = "/site/wopi" + newPath.substring(toReplace.length());
        } else {
            throw new NuxeoException("Cannot forward " + newPath);
        }
        RequestDispatcher rd = req.getRequestDispatcher(newPath);
        rd.forward(req, resp);
    }
}
