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


import java.security.PublicKey;
import java.util.Map;

/**
 * Model representing parameters of the step for sending encrypted data to intermediate server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EncryptStepModel extends BaseStepModel {

    private String dataFileName;
    private String applicationKey;
    private String applicationSecret;
    private PublicKey masterPublicKey;
    private String scope;

    /**
     * Set name of file with request data.
     * @return Data file name.
     */
    public String getDataFileName() {
        return dataFileName;
    }

    /**
     * Set name of file with request data.
     * @param dataFileName Data file name.
     */
    public void setDataFileName(String dataFileName) {
        this.dataFileName = dataFileName;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get application secret.
     * @return Application secret.
     */
    public String getApplicationSecret() {
        return applicationSecret;
    }

    /**
     * Set application secret.
     * @param applicationSecret Application secret.
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Get master public key.
     * @return Master public key.
     */
    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    /**
     * Set master public key.
     * @param masterPublicKey Master public key.
     */
    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    /**
     * Get ECIES encryption scope.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @return ECIES encryption scope.
     */
    public String getScope() {
        return scope;
    }

    /**
     * Set ECIES encryption scope.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param scope ECIES encryption scope.
     */
    public void setScope(String scope) {
        this.scope = scope;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("DATA_FILE_NAME", dataFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("SCOPE", scope);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setDataFileName((String) context.get("DATA_FILE_NAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setScope((String) context.get("SCOPE"));
    }
}
