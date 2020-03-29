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

import java.util.Map;

/**
 * Model representing parameters of the step for verifying token digest.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class VerifyTokenStepModel extends BaseStepModel {

    private String tokenId;
    private String tokenSecret;
    private String httpMethod;
    private String dataFileName;
    private boolean dryRun;

    /**
     * Get token ID.
     * @return Token ID.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Set token ID.
     * @param tokenId Token ID.
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Get token secret.
     * @return Token secret.
     */
    public String getTokenSecret() {
        return tokenSecret;
    }

    /**
     * Set token secret.
     * @param tokenSecret Token secret.
     */
    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getDataFileName() {
        return dataFileName;
    }

    public void setDataFileName(String dataFileName) {
        this.dataFileName = dataFileName;
    }

    /**
     * Set flag indicating that this step should be terminated before the networking call.
     * @return Dry run indicator.
     */
    public boolean isDryRun() {
        return dryRun;
    }

    public void setDryRun(boolean dryRun) {
        this.dryRun = dryRun;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("TOKEN_ID", tokenId);
        context.put("TOKEN_SECRET", tokenSecret);
        context.put("HTTP_METHOD", httpMethod);
        context.put("DATA_FILENAME", dataFileName);
        context.put("DRY_RUN", dryRun);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setTokenId((String) context.get("TOKEN_ID"));
        setTokenSecret((String) context.get("TOKEN_SECRET"));
        setHttpMethod((String) context.get("HTTP_METHOD"));
        setDataFileName((String) context.get("DATA_FILENAME"));
        setDryRun((boolean) context.get("DRY_RUN"));
    }

}
