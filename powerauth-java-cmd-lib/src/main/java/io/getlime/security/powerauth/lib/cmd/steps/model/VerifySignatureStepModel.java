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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import java.util.Map;

/**
 * Model representing parameters of the step for verifying data signature.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class VerifySignatureStepModel extends BaseStepModel {

    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String httpMethod;
    private String resourceId;
    private PowerAuthSignatureTypes signatureType;
    private String dataFileName;
    private String password;
    private boolean dryRun;

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
     * HTTP method used for the request call.
     * @param httpMethod HTTP method for the call.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Resource identifier for a given call.
     * @param resourceId Resource identifier.
     */
    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    /**
     * PowerAuth signature type.
     * @param signatureType Signature type.
     */
    public void setSignatureType(PowerAuthSignatureTypes signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * File with the request data, used for POST, PUT and DELETE methods.
     * @param dataFileName Request data filename.
     */
    public void setDataFileName(String dataFileName) {
        this.dataFileName = dataFileName;
    }

    /**
     * Password for the password related key encryption.
     * @param password Password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Set flag indicating that this step should be terminated before the networking call.
     * @return Dry run indicator.
     */
    public boolean isDryRun() {
        return dryRun;
    }

    public String getStatusFileName() {
        return statusFileName;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getResourceId() {
        return resourceId;
    }

    public PowerAuthSignatureTypes getSignatureType() {
        return signatureType;
    }

    public String getDataFileName() {
        return dataFileName;
    }

    public String getPassword() {
        return password;
    }

    public void setDryRun(boolean dryRun) {
        this.dryRun = dryRun;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("HTTP_METHOD", httpMethod);
        context.put("ENDPOINT", resourceId);
        context.put("SIGNATURE_TYPE", signatureType.toString());
        context.put("DATA_FILE_NAME", dataFileName);
        context.put("PASSWORD", password);
        context.put("DRY_RUN", dryRun);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setHttpMethod((String) context.get("HTTP_METHOD"));
        setResourceId((String) context.get("ENDPOINT"));
        setSignatureType(PowerAuthSignatureTypes.getEnumFromString((String) context.get("SIGNATURE_TYPE")));
        setDataFileName((String) context.get("DATA_FILE_NAME"));
        setPassword((String) context.get("PASSWORD"));
        setDryRun((boolean) context.get("DRY_RUN"));
    }
}
