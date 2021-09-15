/*
 * PowerAuth Command-line utility
 * Copyright 2018 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.powerauth.lib.cmd.steps.model;

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class defining a base for a step model classes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class BaseStepModel implements BaseStepData {

    /**
     * HTTP headers
     */
    private Map<String, String> headers;

    /**
     * Base URI of PowerAuth Standard RESTful API
     */
    private String uriString;

    /**
     * Activation status object
     */
    private ResultStatusObject resultStatusObject;

    /**
     * PowerAuth protocol version
     */
    private PowerAuthVersion version;

    /**
     * Convert this object to map.
     *
     * @return Map representing this object.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("HTTP_HEADERS", headers);
        context.put("URI_STRING", uriString);
        context.put("STATUS_OBJECT", resultStatusObject);
        context.put("VERSION", version);
        return context;
    }

    /**
     * Initialize object with given attribute map.
     *
     * @param context Context with attributes.
     */
    @SuppressWarnings("unchecked")
    public void fromMap(Map<String, Object> context) {
        setHeaders((Map<String, String>) context.get("HTTP_HEADERS"));
        setUriString((String) context.get("URI_STRING"));
        setResultStatusObject((ResultStatusObject) context.get("STATUS_OBJECT"));
        setVersion((PowerAuthVersion) context.get("VERSION"));
    }

}
