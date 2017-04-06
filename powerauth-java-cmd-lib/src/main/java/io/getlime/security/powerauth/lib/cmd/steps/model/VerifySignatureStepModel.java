package io.getlime.security.powerauth.lib.cmd.steps.model;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import org.json.simple.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class VerifySignatureStepModel implements BaseStepModel {

    private String uriString;
    private String statusFileName;
    private String applicationKey;
    private String applicationSecret;
    private String httpMethod;
    private String resourceId;
    private PowerAuthSignatureTypes signatureType;
    private String dataDileName;
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

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public void setSignatureType(PowerAuthSignatureTypes signatureType) {
        this.signatureType = signatureType;
    }

    public void setDataDileName(String dataDileName) {
        this.dataDileName = dataDileName;
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
        context.put("HTTP_METHOD", httpMethod);
        context.put("ENDPOINT", resourceId);
        context.put("SIGNATURE_TYPE", signatureType.toString());
        context.put("DATA_FILE_NAME", dataDileName);
        context.put("PASSWORD", password);
        return context;
    }

}
