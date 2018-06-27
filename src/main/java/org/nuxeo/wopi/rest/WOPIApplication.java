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

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.nuxeo.ecm.webengine.model.io.BlobWriter;

import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;

/**
 * @since 10.3
 */
public class WOPIApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(FilesResource.class);
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        Set<Object> singletons = new HashSet<>();
        singletons.add(new JacksonJsonProvider());
        singletons.add(new BlobWriter());
        return singletons;
    }
}
