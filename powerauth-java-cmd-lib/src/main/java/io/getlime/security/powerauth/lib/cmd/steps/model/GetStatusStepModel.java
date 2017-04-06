package io.getlime.security.powerauth.lib.cmd.steps.model;

import org.json.simple.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class GetStatusStepModel implements BaseStepModel {

    private String uriString;
    private JSONObject resultStatusObject;

    public void setUriString(String uriString) {
        this.uriString = uriString;
    }

    public void setResultStatusObject(JSONObject resultStatusObject) {
        this.resultStatusObject = resultStatusObject;
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = new HashMap<>();
        context.put("URI_STRING", uriString);
        context.put("STATUS_OBJECT", resultStatusObject);
        return context;
    }
}
