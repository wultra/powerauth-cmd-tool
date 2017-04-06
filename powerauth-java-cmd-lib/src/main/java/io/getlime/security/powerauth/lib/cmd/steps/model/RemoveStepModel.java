package io.getlime.security.powerauth.lib.cmd.steps.model;

import org.json.simple.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RemoveStepModel implements BaseStepModel {

    private String uriString;
    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String password;
    private JSONObject resultStatusObject;

    public void setUriString(String uriString) {
        this.uriString = uriString;
    }

    public void setStatusFileName(String statusFileName) {
        this.statusFileName = statusFileName;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setResultStatusObject(JSONObject resultStatusObject) {
        this.resultStatusObject = resultStatusObject;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("URI_STRING", uriString);
        context.put("STATUS_OBJECT", resultStatusObject);
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        return context;
    }

}
