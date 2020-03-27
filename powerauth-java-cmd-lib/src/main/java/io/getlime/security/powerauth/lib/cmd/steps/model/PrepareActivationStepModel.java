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
 * Model representing parameters of the step for preparing a new activation (key exchange).
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PrepareActivationStepModel extends BaseStepModel {

    private String statusFileName;
    private String activationCode;
    private String additionalActivationOtp;
    private String activationName;
    private String platform;
    private String deviceInfo;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private PublicKey masterPublicKey;

    /**
     * Set Master Server Public Key, a value specific for given application.
     * @param masterPublicKey KEY_MASTER_SERVER_PUBLIC.
     */
    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    /**
     * File name of the file with stored activation status.
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Set user device platform.
     * @param platform User device platform.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Set information about user device.
     * @param deviceInfo Information about user device.
     */
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
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
     * Activation code, in following format: "XXXXX-XXXXX-XXXXX-XXXXX" where each "X" is from Base32.
     * @param activationCode Activation code.
     */
    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    /**
     * Additional activation OTP, supported by PowerAuth Server {@code 0.24+}.
     * @param additionalActivationOtp Additional activation OTP.
     */
    public void setAdditionalActivationOtp(String additionalActivationOtp) {
        this.additionalActivationOtp = additionalActivationOtp;
    }

    /**
     * Password for the password related key encryption.
     * @param password Password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    public String getStatusFileName() {
        return statusFileName;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public String getAdditionalActivationOtp() {
        return additionalActivationOtp;
    }

    public String getActivationName() {
        return activationName;
    }

    public String getPlatform() {
        return platform;
    }

    public String getDeviceInfo() {
        return deviceInfo;
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

    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("ACTIVATION_CODE", activationCode);
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
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setActivationCode((String) context.get("ACTIVATION_CODE"));
        setAdditionalActivationOtp((String) context.get("ADDITIONAL_ACTIVATION_OTP"));
        setPassword((String) context.get("PASSWORD"));
        setActivationName((String) context.get("ACTIVATION_NAME"));
        setPlatform((String) context.get("PLATFORM"));
        setDeviceInfo((String) context.get("DEVICE_INFO"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
    }
}
