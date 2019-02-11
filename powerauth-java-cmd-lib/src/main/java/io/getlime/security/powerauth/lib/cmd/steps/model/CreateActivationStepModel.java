package io.getlime.security.powerauth.lib.cmd.steps.model;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Model representing step for creating a custom activation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class CreateActivationStepModel extends BaseStepModel {

    private Map<String, String> identityAttributes;
    private Map<String, Object> customAttributes;
    private String statusFileName;
    private String activationOtp;
    private String activationName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private PublicKey masterPublicKey;

    public CreateActivationStepModel() {
        identityAttributes = new HashMap<>();
        customAttributes = new HashMap<>();
    }

    public Map<String, String> getIdentityAttributes() {
        return identityAttributes;
    }

    public void setIdentityAttributes(Map<String, String> identityAttributes) {
        this.identityAttributes = identityAttributes;
    }

    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    public String getStatusFileName() {
        return statusFileName;
    }

    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    public String getActivationOtp() {
        return activationOtp;
    }

    public void setActivationOtp(String activationOtp) {
        this.activationOtp = activationOtp;
    }

    public String getActivationName() {
        return activationName;
    }

    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public PublicKey getMasterPublicKey() {
        return masterPublicKey;
    }

    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("IDENTITY_ATTRIBUTES", identityAttributes);
        context.put("CUSTOM_ATTRIBUTES", customAttributes);
        context.put("ACTIVATION_OTP", activationOtp);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("PASSWORD", password);
        context.put("ACTIVATION_NAME", activationName);
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
        setActivationOtp((String) context.get("ACTIVATION_OTP"));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setPassword((String) context.get("PASSWORD"));
        setActivationName((String) context.get("ACTIVATION_NAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
    }

}
