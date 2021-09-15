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
 * Model representing step for creating a new token.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class CreateTokenStepModel extends BaseStepModel
        implements SignatureHeaderData, ResultStatusChangeable {

    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private PowerAuthSignatureTypes signatureType;
    private PublicKey masterPublicKey;

    /**
     * File name of the file with stored activation status.
     *
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Application key.
     *
     * @param applicationKey APP_KEY.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Application secret.
     *
     * @param applicationSecret APP_SECRET.
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Password for the password related key encryption.
     *
     * @param password Password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * PowerAuth signature type.
     *
     * @param signatureType Signature type.
     */
    public void setSignatureType(PowerAuthSignatureTypes signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Set master public key
     *
     * @param masterPublicKey Master public key
     */
    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
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

    public String getPassword() {
        return password;
    }

    public PowerAuthSignatureTypes getSignatureType() {
        return signatureType;
    }

    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        context.put("SIGNATURE_TYPE", signatureType.toString());
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
        setSignatureType(PowerAuthSignatureTypes.getEnumFromString((String) context.get("SIGNATURE_TYPE")));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
    }

}
