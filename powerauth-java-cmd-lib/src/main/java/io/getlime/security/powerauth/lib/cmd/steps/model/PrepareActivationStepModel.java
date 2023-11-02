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

import io.getlime.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

/**
 * Model representing parameters of the step for preparing a new activation (key exchange).
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class PrepareActivationStepModel extends BaseStepModel
        implements ActivationData, ResultStatusChangeable, EncryptionHeaderData {

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * Activation code, in following format: "XXXXX-XXXXX-XXXXX-XXXXX" where each "X" is from Base32.
     */
    private String activationCode;

    /**
     * Custom attributes.
     */
    private Map<String, Object> customAttributes;

    /**
     * Additional activation OTP, supported by PowerAuth Server {@code 0.24+}.
     */
    private String additionalActivationOtp;

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
     * Master Server Public Key, a value specific for given application.
     */
    private PublicKey masterPublicKey;

    @Override
    public Map<String, Object> getCustomAttributes() {
        return Collections.emptyMap();
    }

    @Override
    public Map<String, String> getIdentityAttributes() {
        return Collections.emptyMap();
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("ACTIVATION_CODE", activationCode);
        context.put("CUSTOM_ATTRIBUTES", customAttributes);
        context.put("ADDITIONAL_ACTIVATION_OTP", additionalActivationOtp);
        context.put("PASSWORD", password);
        context.put("ACTIVATION_NAME", activationName);
        context.put("PLATFORM", platform);
        context.put("DEVICE_INFO", deviceInfo);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        return context;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setActivationCode((String) context.get("ACTIVATION_CODE"));
        setCustomAttributes((Map<String, Object>) context.get("CUSTOM_ATTRIBUTES"));
        setAdditionalActivationOtp((String) context.get("ADDITIONAL_ACTIVATION_OTP"));
        setPassword((String) context.get("PASSWORD"));
        setActivationName((String) context.get("ACTIVATION_NAME"));
        setPlatform((String) context.get("PLATFORM"));
        setDeviceInfo((String) context.get("DEVICE_INFO"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
    }

}
