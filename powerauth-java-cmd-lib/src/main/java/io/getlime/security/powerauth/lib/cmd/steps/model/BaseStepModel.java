/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

import org.json.simple.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class defining a base for a step model classes.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class BaseStepModel {

    private Map<String, String> headers;
    private String uriString;
    private JSONObject resultStatusObject;

    /**
     * Set base URI string of the PowerAuth 2.0 Standard RESTful API.
     * @param uriString Base URI of PA2.0 Standard RESTful API.
     */
    public void setUriString(String uriString) {
        this.uriString = uriString;
    }

    /**
     * Set the object representing activation status.
     * @param resultStatusObject Activation status object.
     */
    public void setResultStatusObject(JSONObject resultStatusObject) {
        this.resultStatusObject = resultStatusObject;
    }

    /**
     * Set HTTP headers used for requests.
     * @param headers HTTP headers.
     */
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getUriString() {
        return uriString;
    }

    public JSONObject getResultStatusObject() {
        return resultStatusObject;
    }

    /**
     * Convert this object to map.
     * @return Map representing this object.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("HTTP_HEADERS", headers);
        context.put("URI_STRING", uriString);
        context.put("STATUS_OBJECT", resultStatusObject);
        return context;
    }

    /**
     * Initialize object with given attribute map.
     * @param context Context with attributes.
     */
    public void fromMap(Map<String, Object> context) {
        setHeaders((Map<String, String>) context.get("HTTP_HEADERS"));
        setUriString((String) context.get("URI_STRING"));
        setResultStatusObject((JSONObject) context.get("STATUS_OBJECT"));
    }

}
