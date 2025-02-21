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
package com.wultra.security.powerauth.lib.cmd.steps.model;

import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import lombok.Data;
import org.json.simple.JSONObject;

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
     * URL used for the request.
     */
    private String uriString;

    /**
     * Base URI of PowerAuth Standard RESTful API.
     */
    private String baseUriString;

    /**
     * Activation status object
     */
    private ResultStatusObject resultStatusObject;

    /**
     * PowerAuth protocol version
     */
    private PowerAuthVersion version;

    /**
     * @return Activation status as JSON object.
     */
    public JSONObject getResultStatusObject() {
        return resultStatusObject != null ? resultStatusObject.getJsonObject() : null;
    }

    /**
     * Sets activation status object from JSON object
     * @param jsonObject Activation status object as JSON
     */
    public void setResultStatusObject(JSONObject jsonObject) {
        this.resultStatusObject = ResultStatusObject.fromJsonObject(jsonObject);
    }

    /**
     * @return Activation status
     */
    public ResultStatusObject getResultStatus() {
        return resultStatusObject;
    }

    /**
     * Sets activation status object
     * @param resultStatusObject Activation status object
     */
    public void setResultStatus(ResultStatusObject resultStatusObject) {
        this.resultStatusObject = resultStatusObject;
    }

    /**
     * Sets the version value
     * <p>the PowerAuth version is detected from the provided value</p>
     * @param versionValue string version value, must correspond with any of {@link PowerAuthVersion}
     */
    public void setVersion(String versionValue) {
        this.version = PowerAuthVersion.fromValue(versionValue);
    }

    /**
     * Sets the version value
     * @param version PowerAuth version value
     */
    public void setVersion(PowerAuthVersion version) {
        this.version = version;
    }

    /**
     * Convert this object to map.
     *
     * @return Map representing this object.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("HTTP_HEADERS", headers);
        context.put("URI_STRING", uriString);
        context.put("BASE_URI_STRING", baseUriString);
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
        setBaseUriString((String) context.get("BASE_URI_STRING"));
        Object statusObject = context.get("STATUS_OBJECT");
        if (statusObject instanceof JSONObject) {
            setResultStatus(ResultStatusObject.fromJsonObject((JSONObject) statusObject));
        } else if (statusObject instanceof ResultStatusObject) {
            setResultStatus((ResultStatusObject) statusObject);
        }
        Object version = context.get("VERSION");
        if (version instanceof PowerAuthVersion) {
            setVersion((PowerAuthVersion) version);
        } else if (version instanceof String) {
            setVersion(PowerAuthVersion.fromValue((String) version));
        }
    }

}
