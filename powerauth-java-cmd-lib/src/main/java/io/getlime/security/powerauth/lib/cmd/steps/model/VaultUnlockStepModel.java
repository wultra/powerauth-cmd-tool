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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import java.util.Map;

/**
 * Model representing parameters of the step for unlocking secure vault.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class VaultUnlockStepModel extends BaseStepModel {

    private String applicationKey;
    private String applicationSecret;
    private String statusFileName;
    private PowerAuthSignatureTypes signatureType;
    private String password;
    private String reason;

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
     * File name of the file with stored activation status.
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * PowerAuth 2.0 signature type.
     * @param signatureType Signature type.
     */
    public void setSignatureType(PowerAuthSignatureTypes signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Password for the password related key encryption.
     * @param password Password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public String getStatusFileName() {
        return statusFileName;
    }

    public PowerAuthSignatureTypes getSignatureType() {
        return signatureType;
    }

    public String getPassword() {
        return password;
    }

    /**
     * Get reason why vault is being unlocked.
     * @return Reason why vault is being unlocked.
     */
    public String getReason() {
        return reason;
    }

    /**
     * Set reason why vault is being unlocked.
     * @param reason Reason why vault is being unlocked.
     */
    public void setReason(String reason) {
        this.reason = reason;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("SIGNATURE_TYPE", signatureType.toString());
        context.put("PASSWORD", password);
        context.put("REASON", reason);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setSignatureType(PowerAuthSignatureTypes.getEnumFromString((String) context.get("SIGNATURE_TYPE")));
        setPassword((String) context.get("PASSWORD"));
        setReason((String) context.get("REASON"));
    }
}
