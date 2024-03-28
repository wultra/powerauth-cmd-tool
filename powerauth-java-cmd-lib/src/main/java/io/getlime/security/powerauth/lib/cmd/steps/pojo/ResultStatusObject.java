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
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Activation status object
 *
 * <p>
 *     setters used in JSON deserialization
 * </p>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@SuppressWarnings("unchecked")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResultStatusObject {

    private static final Logger logger = LoggerFactory.getLogger(ResultStatusObject.class);

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Backward compatibility, sync all modifications to the JSON object
     */
    @JsonIgnore
    private JSONObject jsonObject = new JSONObject();

    /**
     * @return Activation ID
     */
    public String getActivationId() {
        return (String) jsonObject.get("activationId");
    }

    /**
     * Sets activation ID
     * @param activationId Activation ID value
     */
    public void setActivationId(String activationId) {
        jsonObject.put("activationId", activationId);
    }

    /**
     * @return Counter
     */
    public Long getCounter() {
        return (Long) jsonObject.get("counter");
    }

    /**
     * Sets counter value
     * @param counter Counter value
     */
    public void setCounter(Long counter) {
        jsonObject.put("counter", counter);
    }

    /**
     * @return Counter data
     */
    public String getCtrData() {
        return (String) jsonObject.get("ctrData");
    }

    /**
     * Sets counter data
     * @param ctrData Counter data
     */
    public void setCtrData(String ctrData) {
        jsonObject.put("ctrData", ctrData);
    }

    /**
     * @return Byte representation of the encrypted device private key
     */
    @JsonIgnore
    public byte[] getEncryptedDevicePrivateKeyBytes() {
        String encryptedDevicePrivateKey = (String) jsonObject.get("encryptedDevicePrivateKey");
        return Base64.getDecoder().decode(encryptedDevicePrivateKey);
    }

    /**
     * Sets encrypted device private key
     * @param encryptedDevicePrivateKeyBytes Encrypted device private key bytes
     */
    @JsonIgnore
    public void setEncryptedDevicePrivateKeyBytes(byte[] encryptedDevicePrivateKeyBytes) {
        String encryptedDevicePrivateKey = Base64.getEncoder().encodeToString(encryptedDevicePrivateKeyBytes);
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    /**
     * @return Base64 encoded byte representation of the encrypted device private key
     */
    public String getEncryptedDevicePrivateKey() {
        return (String) jsonObject.get("encryptedDevicePrivateKey");
    }

    /**
     * Sets encrypted device private key object
     * @param encryptedDevicePrivateKey Encrypted device private key object
     */
    public void setEncryptedDevicePrivateKey(String encryptedDevicePrivateKey) {
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    /**
     * @return Response data
     */
    public String getResponseData() {
        return (String) jsonObject.get("responseData");
    }

    /**
     * Sets response data
     * @param responseData Response data
     */
    public void setResponseData(String responseData) {
        jsonObject.put("responseData", responseData);
    }

    /**
     * @return Server public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getServerPublicKeyObject() throws Exception {
        String serverPublicKey = (String) jsonObject.get("serverPublicKey");
        return KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(serverPublicKey));
    }

    /**
     * Sets server public key object
     * @param serverPublicKeyObject Public key object
     * @throws Exception when the public key cannot be encoded
     */
    @JsonIgnore
    public void setServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPublicKeyToBytes(serverPublicKeyObject));
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    /**
     * @return Base64 encoded byte representation of the server public key
     */
    public String getServerPublicKey() {
        return (String) jsonObject.get("serverPublicKey");
    }

    /**
     * Sets server public key
     * @param serverPublicKey Public key as base64
     */
    public void setServerPublicKey(String serverPublicKey) {
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    /**
     * @return Signature biometry key
     */
    @JsonIgnore
    public SecretKey getSignatureBiometryKeyObject() {
        final String signatureBiometryKey = (String) jsonObject.get("signatureBiometryKey");
        if (signatureBiometryKey == null) {
            return null;
        }
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(signatureBiometryKey));
    }

    /**
     * Sets signature biometry key object
     * @param signatureBiometryKeyObject Signature biometry key object
     */
    @JsonIgnore
    public void setSignatureBiometryKeyObject(SecretKey signatureBiometryKeyObject) {
        String signatureBiometryKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signatureBiometryKeyObject));
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    /**
     * @return Base64 encoded byte representation of the signature biometry key
     */
    public String getSignatureBiometryKey() {
        return (String) jsonObject.get("signatureBiometryKey");
    }

    /**
     * Sets signature biometry key
     * @param signatureBiometryKey Signature biometry key
     */
    public void setSignatureBiometryKey(String signatureBiometryKey) {
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    /**
     * @return Byte representation of the signature knowledge key
     */
    @JsonIgnore
    public byte[] getSignatureKnowledgeKeyEncryptedBytes() {
        String signatureKnowledgeKeyEncrypted = (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
        return Base64.getDecoder().decode(signatureKnowledgeKeyEncrypted);
    }

    /**
     * Sets signature knowledge key encrypted bytes
     * @param signatureKnowledgeKeyEncryptedBytes Signature knowledge key encrypted bytes
     */
    @JsonIgnore
    public void setSignatureKnowledgeKeyEncryptedBytes(byte[] signatureKnowledgeKeyEncryptedBytes) {
        String signatureKnowledgeKeyEncrypted = Base64.getEncoder().encodeToString(signatureKnowledgeKeyEncryptedBytes);
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    /**
     * @return Base64 encoded byte representation of the signature knowledge key
     */
    public String getSignatureKnowledgeKeyEncrypted() {
        return (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
    }

    /**
     * Sets signature knowledge key encrypted values
     * @param signatureKnowledgeKeyEncrypted Signature knowledge key encrypted value
     */
    public void setSignatureKnowledgeKeyEncrypted(String signatureKnowledgeKeyEncrypted) {
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    /**
     * @return Signature knowledge key salt bytes
     */
    @JsonIgnore
    public byte[] getSignatureKnowledgeKeySaltBytes() {
        String signatureKnowledgeKeySalt = (String) jsonObject.get("signatureKnowledgeKeySalt");
        return Base64.getDecoder().decode(signatureKnowledgeKeySalt);
    }

    /**
     * Sets signature knowledge key salt bytes
     * @param signatureKnowledgeKeySaltBytes Signature knowledge key salt bytes
     */
    @JsonIgnore
    public void setSignatureKnowledgeKeySaltBytes(byte[] signatureKnowledgeKeySaltBytes) {
        String signatureKnowledgeKeySalt = Base64.getEncoder().encodeToString(signatureKnowledgeKeySaltBytes);
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    /**
     * @return Signature knowledge salt
     */
    public String getSignatureKnowledgeKeySalt() {
        return (String) jsonObject.get("signatureKnowledgeKeySalt");
    }

    /**
     * Sets signature knowledge key salt
     * @param signatureKnowledgeKeySalt Signature knowledge key salt value
     */
    public void setSignatureKnowledgeKeySalt(String signatureKnowledgeKeySalt) {
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    /**
     * @return Signature possession key
     */
    @JsonIgnore
    public SecretKey getSignaturePossessionKeyObject() {
        final String signaturePossessionKey = (String) jsonObject.get("signaturePossessionKey");
        if (signaturePossessionKey == null) {
            return null;
        }
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(signaturePossessionKey));
    }

    /**
     * Sets signature possession key object
     * @param signaturePossessionKeyObject Signature possession key object value
     */
    @JsonIgnore
    public void setSignaturePossessionKeyObject(SecretKey signaturePossessionKeyObject) {
        String signaturePossessionKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signaturePossessionKeyObject));
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    /**
     * @return Base64 encoded byte representation of the signature possession key
     */
    public String getSignaturePossessionKey() {
        return (String) jsonObject.get("signaturePossessionKey");
    }

    /**
     * Sets signature possession key
     * @param signaturePossessionKey Base64 encoded byte representation of the signature possession key
     */
    public void setSignaturePossessionKey(String signaturePossessionKey) {
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    /**
     * @return Transport master key object value
     */
    @JsonIgnore
    public SecretKey getTransportMasterKeyObject() {
        final String transportMasterKey = (String) jsonObject.get("transportMasterKey");
        if (transportMasterKey == null) {
            return null;
        }
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKey));
    }

    /**
     * Sets transport master key object
     * @param transportMasterKeyObject Transport master key object value
     */
    @JsonIgnore
    public void setTransportMasterKeyObject(SecretKey transportMasterKeyObject) {
        String transportMasterKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKeyObject));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    /**
     * @return Base64 encoded byte representation of the transport master key
     */
    public String getTransportMasterKey() {
        return (String) jsonObject.get("transportMasterKey");
    }

    /**
     * Sets transport master key value
     * @param transportMasterKey Base64 encoded byte representation of the transport master key
     */
    public void setTransportMasterKey(String transportMasterKey) {
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    /**
     * @return Used PowerAuth version
     */
    public Long getVersion() {
        return (Long) jsonObject.get("version");
    }

    /**
     * Sets version
     * @param version Version value
     */
    public void setVersion(Long version) {
        jsonObject.put("version", version);
    }

    /**
     * Converts JSON data to an activation status object
     * @param jsonObject JSON data
     * @return Activation status object created from the JSON data
     */
    public static ResultStatusObject fromJsonObject(JSONObject jsonObject) {
        ResultStatusObject resultStatusObject;
        try {
            resultStatusObject = new ResultStatusObject();
            resultStatusObject.setJsonObject(jsonObject);
        } catch (Exception e) {
            logger.error("Invalid json data specified for result status object", e);
            resultStatusObject = new ResultStatusObject();
        }
        return resultStatusObject;
    }

}
