/*
 * Copyright 2019 Wultra s.r.o.
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

import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Model representing step for creating a custom activation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class CreateActivationStepModel extends BaseStepModel
        implements ActivationData, ResultStatusChangeable, EncryptionHeaderData {

    /**
     * Identity attributes.
     */
    private Map<String, String> identityAttributes;

    /**
     * Custom attributes.
     */
    private Map<String, Object> customAttributes;

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * Activation OTP.
     */
    private String activationOtp;

    /**
     * Activation name.
     */
    private String activationName;

    /**
     * User device platform
     */
    private String platform;

    /**
     * Information about user device.
     */
    private String deviceInfo;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Application secret.
     */
    private String applicationSecret;

    /**
     * Password for the password related key encryption.
     */
    private String password;

    /**
     * Master Server Public Key for P-256, a value specific for given application.
     */
    private PublicKey masterPublicKeyP256;

    /**
     * Master Server Public Key for P-384, a value specific for given application.
     */
    private PublicKey masterPublicKeyP384;

    /**
     * Master Server Public Key for ML-DSA-65, a value specific for given application.
     */
    private PublicKey masterPublicKeyMlDsa65;

    /**
     * Algorithm used for the shared secret derivation.
     */
    private SharedSecretAlgorithm sharedSecretAlgorithm;

    /**
     * Constructor
     */
    public CreateActivationStepModel() {
        identityAttributes = new HashMap<>();
        customAttributes = new HashMap<>();
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("IDENTITY_ATTRIBUTES", identityAttributes);
        context.put("CUSTOM_ATTRIBUTES", customAttributes);
        context.put("ACTIVATION_OTP", activationOtp);
        context.put("MASTER_PUBLIC_KEY_P256", masterPublicKeyP256);
        context.put("MASTER_PUBLIC_KEY_P384", masterPublicKeyP384);
        context.put("MASTER_PUBLIC_KEY_MLDSA65", masterPublicKeyMlDsa65);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("PASSWORD", password);
        context.put("ACTIVATION_NAME", activationName);
        context.put("PLATFORM", platform);
        context.put("DEVICE_INFO", deviceInfo);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("SHARED_SECRET_ALGORITHM", sharedSecretAlgorithm);
        return context;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setIdentityAttributes((Map<String, String>) context.get("IDENTITY_ATTRIBUTES"));
        setCustomAttributes((Map<String, Object>) context.get("CUSTOM_ATTRIBUTES"));
        setActivationOtp((String) context.get("ACTIVATION_OTP"));
        setMasterPublicKeyP256((PublicKey) context.get("MASTER_PUBLIC_KEY_P256"));
        setMasterPublicKeyP384((PublicKey) context.get("MASTER_PUBLIC_KEY_P384"));
        setMasterPublicKeyMlDsa65((PublicKey) context.get("MASTER_PUBLIC_KEY_MLDSA65"));
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setPassword((String) context.get("PASSWORD"));
        setActivationName((String) context.get("ACTIVATION_NAME"));
        setPlatform((String) context.get("PLATFORM"));
        setDeviceInfo((String) context.get("DEVICE_INFO"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setSharedSecretAlgorithm((SharedSecretAlgorithm) context.get("SHARED_SECRET_ALGORITHM"));
    }

}
