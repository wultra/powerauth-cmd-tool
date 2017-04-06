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
 * Model representing parameters of the step for removing activation.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RemoveStepModel implements BaseStepModel {

    private String uriString;
    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
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
     * File name of the file with stored activation status.
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Application key.
     * @param applicationKey APP_KEY.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Application secret.
     * @param applicationSecret APP_SECRET.
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Password for the password related key encryption.
     * @param password Password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("URI_STRING", uriString);
        context.put("STATUS_OBJECT", resultStatusObject);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        return context;
    }

}
