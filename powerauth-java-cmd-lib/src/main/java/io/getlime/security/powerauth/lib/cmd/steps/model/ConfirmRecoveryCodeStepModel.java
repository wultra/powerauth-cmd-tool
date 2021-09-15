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
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;

import java.security.PublicKey;
import java.util.Map;

/**
 * Model representing step for confirming recovery code.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ConfirmRecoveryCodeStepModel extends BaseStepModel
        implements ResultStatusChangeable, SignatureHeaderData {

    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private String recoveryCode;
    private PublicKey masterPublicKey;

    /**
     * Get file name of the file with stored activation status.
     *
     * @return Status file name.
     */
    public String getStatusFileName() {
        return statusFileName;
    }

    /**
     * File name of the file with stored activation status.
     *
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Get application key.
     *
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Application key.
     *
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get application secret.
     *
     * @return Application secret.
     */
    public String getApplicationSecret() {
        return applicationSecret;
    }

    /**
     * Application secret.
     *
     * @param applicationSecret Application secret.
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Get knowledge key password.
     *
     * @return Knowledge key password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Set knowledge key password.
     *
     * @param password Knowledge key password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Get recovery code.
     *
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code.
     *
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }

    /**
     * Get Base64 encoded master public key.
     *
     * @return Base64 encoded master public key.
     */
    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    /**
     * Set master public key
     *
     * @param masterPublicKey Master public key
     */
    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    @Override
    public PowerAuthSignatureTypes getSignatureType() {
        return PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        context.put("RECOVERY_CODE", recoveryCode);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setPassword((String) context.get("PASSWORD"));
        setRecoveryCode((String) context.get("RECOVERY_CODE"));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
    }

}
