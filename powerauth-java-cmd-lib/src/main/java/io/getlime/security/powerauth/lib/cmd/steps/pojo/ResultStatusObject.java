/*
 * Copyright 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.steps.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.security.PublicKey;

/**
 * Activation status object
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@SuppressWarnings("unchecked")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResultStatusObject {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Backward compatibility, sync all modifications to the JSON object
     */
    @JsonIgnore
    private JSONObject jsonObject = new JSONObject();

    public String getActivationId() {
        return (String) jsonObject.get("activationId");
    }

    public void setActivationId(String activationId) {
        jsonObject.put("activationId", activationId);
    }

    public Long getCounter() {
        return (Long) jsonObject.get("counter");
    }

    public void setCounter(Long counter) {
        jsonObject.put("counter", counter);
    }

    public String getCtrData() {
        return (String) jsonObject.get("ctrData");
    }

    public void setCtrData(String ctrData) {
        jsonObject.put("ctrData", ctrData);
    }

    @JsonIgnore
    public byte[] getEncryptedDevicePrivateKeyBytes() {
        String encryptedDevicePrivateKey = (String) jsonObject.get("encryptedDevicePrivateKey");
        return BaseEncoding.base64().decode(encryptedDevicePrivateKey);
    }

    @JsonIgnore
    public void setEncryptedDevicePrivateKeyBytes(byte[] encryptedDevicePrivateKeyBytes) {
        String encryptedDevicePrivateKey = BaseEncoding.base64().encode(encryptedDevicePrivateKeyBytes);
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    public String getEncryptedDevicePrivateKey() {
        return (String) jsonObject.get("encryptedDevicePrivateKey");
    }

    public void setEncryptedDevicePrivateKey(String encryptedDevicePrivateKey) {
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    public String getResponseData() {
        return (String) jsonObject.get("responseData");
    }

    public void setResponseData(String responseData) {
        jsonObject.put("responseData", responseData);
    }

    @JsonIgnore
    public PublicKey getServerPublicKeyObject() throws Exception {
        String serverPublicKey = (String) jsonObject.get("serverPublicKey");
        return KEY_CONVERTOR.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKey));
    }

    @JsonIgnore
    public void setServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        String serverPublicKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertPublicKeyToBytes(serverPublicKeyObject));
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    public String getServerPublicKey() {
        return (String) jsonObject.get("serverPublicKey");
    }

    public void setServerPublicKey(String serverPublicKey) throws Exception {
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    @JsonIgnore
    public SecretKey getSignatureBiometryKeyObject() {
        String signatureBiometryKey = (String) jsonObject.get("signatureBiometryKey");
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signatureBiometryKey));
    }

    @JsonIgnore
    public void setSignatureBiometryKeyObject(SecretKey signatureBiometryKeyObject) {
        String signatureBiometryKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signatureBiometryKeyObject));
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    public String getSignatureBiometryKey() {
        return (String) jsonObject.get("signatureBiometryKey");
    }

    public void setSignatureBiometryKey(String signatureBiometryKey) {
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    @JsonIgnore
    public byte[] getSignatureKnowledgeKeyEncryptedBytes() {
        String signatureKnowledgeKeyEncrypted = (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
        return BaseEncoding.base64().decode(signatureKnowledgeKeyEncrypted);
    }

    @JsonIgnore
    public void setSignatureKnowledgeKeyEncryptedBytes(byte[] signatureKnowledgeKeyEncryptedBytes) {
        String signatureKnowledgeKeyEncrypted = BaseEncoding.base64().encode(signatureKnowledgeKeyEncryptedBytes);
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    public String getSignatureKnowledgeKeyEncrypted() {
        return (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
    }

    public void setSignatureKnowledgeKeyEncrypted(String signatureKnowledgeKeyEncrypted) {
        //this.signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(signatureKnowledgeKeyEncrypted);
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    @JsonIgnore
    public byte[] getSignatureKnowledgeKeySaltBytes() {
        String signatureKnowledgeKeySalt = (String) jsonObject.get("signatureKnowledgeKeySalt");
        return BaseEncoding.base64().decode(signatureKnowledgeKeySalt);
    }

    @JsonIgnore
    public void setSignatureKnowledgeKeySaltBytes(byte[] signatureKnowledgeKeySaltBytes) {
        String signatureKnowledgeKeySalt = BaseEncoding.base64().encode(signatureKnowledgeKeySaltBytes);
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    public String getSignatureKnowledgeKeySalt() {
        return (String) jsonObject.get("signatureKnowledgeKeySalt");
    }

    public void setSignatureKnowledgeKeySalt(String signatureKnowledgeKeySalt) {
        //this.signatureKnowledgeKeySaltBytes = BaseEncoding.base64().decode(signatureKnowledgeKeySalt);
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    @JsonIgnore
    public SecretKey getSignaturePossessionKeyObject() {
        String signaturePossessionKey = (String) jsonObject.get("signaturePossessionKey");
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signaturePossessionKey));
    }

    @JsonIgnore
    public void setSignaturePossessionKeyObject(SecretKey signaturePossessionKeyObject) {
        String signaturePossessionKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signaturePossessionKeyObject));
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    public String getSignaturePossessionKey(String signaturePossessionKey) {
        return (String) jsonObject.get("signaturePossessionKey");
    }

    public void setSignaturePossessionKey(String signaturePossessionKey) {
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    @JsonIgnore
    public SecretKey getTransportMasterKeyObject() {
        String transportMasterKey = (String) jsonObject.get("transportMasterKey");
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKey));
    }

    @JsonIgnore
    public void setTransportMasterKeyObject(SecretKey transportMasterKeyObject) {
        String transportMasterKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKeyObject));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    public String getTransportMasterKey() {
        return (String) jsonObject.get("transportMasterKey");
    }

    public void setTransportMasterKey(String transportMasterKey) {
        //this.transportMasterKeyObject = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKey));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    public Long getVersion() {
        return (Long) jsonObject.get("version");
    }

    public void setVersion(Long version) {
        jsonObject.put("version", version);
    }

    public static ResultStatusObject fromJsonObject(JSONObject jsonObject) {
        ResultStatusObject resultStatusObject;
        try {
            resultStatusObject = new ResultStatusObject();
            resultStatusObject.setJsonObject(jsonObject);
        } catch (Exception e) {
            System.err.println("Invalid json data specified for result status object");
            e.printStackTrace(System.err);
            resultStatusObject = new ResultStatusObject();
        }
        return resultStatusObject;
    }

}
