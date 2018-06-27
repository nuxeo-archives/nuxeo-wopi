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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

/**
 * @since 10.3
 */
@AutoValue
@JsonDeserialize(builder = AutoValue_FileInfo.Builder.class)
@JsonInclude(Include.NON_NULL)
public abstract class FileInfo {

    public static FileInfo.Builder builder() {
        return new AutoValue_FileInfo.Builder();
    }

    // -------- Required properties ---------------

    @JsonProperty("BaseFileName")
    public abstract String baseFileName();

    @JsonProperty("OwnerId")
    public abstract String ownerId();

    @JsonProperty("Size")
    public abstract long size();

    @JsonProperty("UserId")
    public abstract String userId();

    @JsonProperty("Version")
    public abstract String version();

    // -------- Host capabilities properties ---------------

    @JsonProperty("SupportsLocks")
    public abstract boolean supportsLocks();

    @JsonProperty("SupportsUpdate")
    public abstract boolean supportsUpdate();

    @JsonProperty("SupportsDeleteFile")
    public abstract boolean supportsDeleteFile();

    // -------- User metadata properties ---------------

    @JsonProperty("IsAnonymousUser")
    public abstract boolean isAnonymousUser();

    @JsonProperty("UserFriendlyName")
    public abstract String userFriendlyName();

    // -------- User permissions properties ---------------

    @JsonProperty("ReadOnly")
    public abstract boolean readOnly();

    @JsonProperty("UserCanRename")
    public abstract boolean userCanRename();

    @JsonProperty("UserCanWrite")
    public abstract boolean userCanWrite();

    // -------- File URL properties ---------------

    // -------- Breadcrumb properties ---------------

    @AutoValue.Builder
    public interface Builder {

        // -------- Required properties ---------------

        @JsonProperty("BaseFileName")
        FileInfo.Builder baseFileName(String baseFileName);

        @JsonProperty("OwnerId")
        FileInfo.Builder ownerId(String ownerId);

        @JsonProperty("Size")
        FileInfo.Builder size(long size);

        @JsonProperty("UserId")
        FileInfo.Builder userId(String userId);

        @JsonProperty("Version")
        FileInfo.Builder version(String version);

        // -------- Host capabilities properties ---------------

        @JsonProperty("SupportsLocks")
        FileInfo.Builder supportsLocks(boolean supportsLocks);

        @JsonProperty("SupportsUpdate")
        FileInfo.Builder supportsUpdate(boolean supportsUpdate);

        @JsonProperty("SupportsDeleteFile")
        FileInfo.Builder supportsDeleteFile(boolean supportsDeleteFile);

        // -------- User metadata properties ---------------

        @JsonProperty("IsAnonymousUser")
        FileInfo.Builder isAnonymousUser(boolean anonymousUser);

        @JsonProperty("UserFriendlyName")
        FileInfo.Builder userFriendlyName(String userFriendlyName);

        // -------- User permissions properties ---------------

        @JsonProperty("ReadOnly")
        FileInfo.Builder readOnly(boolean readOnly);

        @JsonProperty("UserCanRename")
        FileInfo.Builder userCanRename(boolean userCanRename);

        @JsonProperty("UserCanWrite")
        FileInfo.Builder userCanWrite(boolean userCanWrite);

        FileInfo build();
    }
}
