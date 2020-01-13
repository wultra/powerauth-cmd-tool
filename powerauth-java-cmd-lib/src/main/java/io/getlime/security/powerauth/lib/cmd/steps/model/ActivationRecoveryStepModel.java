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
package io.getlime.security.powerauth.lib.cmd.steps.model;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Model representing step for creating an activation using recovery code.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ActivationRecoveryStepModel extends BaseStepModel {

    private Map<String, String> identityAttributes;
    private Map<String, Object> customAttributes;
    private String statusFileName;
    private String activationName;
    private String platform;
    private String deviceInfo;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private PublicKey masterPublicKey;

    /**
     * Default constructor.
     */
    public ActivationRecoveryStepModel() {
        customAttributes = new HashMap<>();
    }

    /**
     * Get identity attributes.
     * @return Identity attributes.
     */
    public Map<String, String> getIdentityAttributes() {
        return identityAttributes;
    }

    /**
     * Set identity attributes.
     * @param identityAttributes Identity attributes.
     */
    public void setIdentityAttributes(Map<String, String> identityAttributes) {
        this.identityAttributes = identityAttributes;
    }

    /**
     * Get custom attributes.
     * @return Custom attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Set custom attributes.
     * @param customAttributes Custom attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    /**
     * Get file name of the file with stored activation status.
     * @return Status file name.
     */
    public String getStatusFileName() {
        return statusFileName;
    }

    /**
     * Set file name of the file with stored activation status.
     * @param statusFileName Status file name.
     */
    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    /**
     * Get activation name.
     * @return Activation name.
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get user device platform.
     * @return User device platform.
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Set user device platform.
     * @param platform User device platform.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Get information about user device.
     * @return Information about user device.
     */
    public String getDeviceInfo() {
        return deviceInfo;
    }

    /**
     * Set information about user device.
     * @param deviceInfo Information about user device.
     */
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
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
     * Get knowledge key password.
     * @return Knowledge key password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Set knowledge key password.
     * @param password Knowledge key password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Get Base64 encoded master public key.
     * @return Base64 encoded master public key.
     */
    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    /**
     * Set Base64 encoded master public key.
     * @param masterPublicKey Base64 encoded master public key.
     */
    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("IDENTITY_ATTRIBUTES", identityAttributes);
        context.put("CUSTOM_ATTRIBUTES", customAttributes);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("STATUS_FILENAME", statusFileName);
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
        setIdentityAttributes((Map<String, String>) context.get("IDENTITY_ATTRIBUTES"));
        setCustomAttributes((Map<String, Object>) context.get("CUSTOM_ATTRIBUTES"));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setPassword((String) context.get("PASSWORD"));
        setActivationName((String) context.get("ACTIVATION_NAME"));
        setPlatform((String) context.get("PLATFORM"));
        setDeviceInfo((String) context.get("DEVICE_INFO"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
    }

}
