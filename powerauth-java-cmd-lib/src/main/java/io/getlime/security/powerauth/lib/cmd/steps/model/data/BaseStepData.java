/*
 * PowerAuth Command-line utility
 * Copyright 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.steps.model.data;

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.json.simple.JSONObject;

import java.util.Map;

/**
 * Data available in each step
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public interface BaseStepData {

    /**
     * @return HTTP headers
     */
    Map<String, String> getHeaders();

    /**
     * @return Activation status object as JSON
     */
    JSONObject getResultStatusObject();

    /**
     * @return Activation status objectø
     */
    ResultStatusObject getResultStatus();

    /**
     * @return Base URI of PowerAuth Standard RESTful API
     */
    String getUriString();

    /**
     * @return PowerAuth protocol version
     */
    PowerAuthVersion getVersion();

    /**
     * Convert this object to a map.
     *
     * @return Map representing this object.
     */
    Map<String, Object> toMap();

    /**
     * Initialize object with given attribute map.
     *
     * @param context Context with attributes.
     */
    void fromMap(Map<String, Object> context);

}
