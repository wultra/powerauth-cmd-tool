package io.getlime.security.powerauth.lib.cmd.steps.model;

import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PrepareActivationStepModel implements BaseStepModel {

    private String uriString;
    private String statusFileName;
    private String activationCode;
    private String activationName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private PublicKey masterPublicKey;
    private JSONObject resultStatusObject;

    public void setUriString(String uriString) {
        this.uriString = uriString;
    }

    public void setMasterPublicKey(PublicKey masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }

    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public void setResultStatusObject(JSONObject resultStatusObject) {
        this.resultStatusObject = resultStatusObject;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("URI_STRING", uriString);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("STATUS_OBJECT", resultStatusObject);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("ACTIVATION_CODE", activationCode);
        context.put("PASSWORD", password);
        context.put("ACTIVATION_NAME", activationName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        return context;
    }

}
