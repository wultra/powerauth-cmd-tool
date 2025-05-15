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
package com.wultra.security.powerauth.lib.cmd.steps.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
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
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SuppressWarnings("unchecked")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResultStatusObject {

    private static final Logger logger = LoggerFactory.getLogger(ResultStatusObject.class);

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();

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
     * @return Server EC public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getEcServerPublicKeyObject() throws Exception {
        int version = getVersion().intValue();
        return switch (version) {
            case 3 -> {
                String serverPublicKey = (String) jsonObject.get("serverPublicKey");
                yield KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(serverPublicKey));
            }
            case 4 -> {
                String serverPublicKey = (String) jsonObject.get("ecServerPublicKey");
                yield KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode(serverPublicKey));
            }
            default -> throw new IllegalStateException("Unsupported version: " + version);
        };
    }

    /**
     * Sets EC server public key object
     * @param serverPublicKeyObject Public key object
     * @throws Exception when the public key cannot be encoded
     */
    @JsonIgnore
    public void setEcServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        int version = getVersion().intValue();
        switch (version) {
            case 3 -> {
                String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P256, serverPublicKeyObject));
                jsonObject.put("serverPublicKey", serverPublicKey);
            }
            case 4 -> {
                String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P256, serverPublicKeyObject));
                jsonObject.put("ecServerPublicKey", serverPublicKey);
            }
            default -> throw new IllegalStateException("Unsupported version: " + version);
        }
    }

    /**
     * @return Base64 encoded byte representation of the EC server public key
     */
    public String getEcServerPublicKey() {
        int version = getVersion().intValue();
        return switch (version) {
            case 3 -> (String) jsonObject.get("serverPublicKey");
            case 4 -> (String) jsonObject.get("ecServerPublicKey");
            default -> throw new IllegalStateException("Unsupported version: " + version);
        };
    }

    /**
     * Sets EC server public key
     * @param serverPublicKey Public key as base64
     */
    public void setEcServerPublicKey(String serverPublicKey) {
        int version = getVersion().intValue();
        switch (version) {
            case 3 -> jsonObject.put("serverPublicKey", serverPublicKey);
            case 4 -> jsonObject.put("ecServerPublicKey", serverPublicKey);
            default -> throw new IllegalStateException("Unsupported version: " + version);
        }
    }

    /**
     * @return Server PQC public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getPqcServerPublicKeyObject() throws Exception {
        String serverPublicKey = (String) jsonObject.get("pqcServerPublicKey");
        return KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(Base64.getDecoder().decode(serverPublicKey));
    }

    /**
     * Sets PQC server public key object
     * @param serverPublicKeyObject Public key object
     * @throws Exception when the public key cannot be encoded
     */
    @JsonIgnore
    public void setPQCServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(serverPublicKeyObject));
        jsonObject.put("pqcServerPublicKey", serverPublicKey);
    }

    /**
     * @return Base64 encoded byte representation of the PQC server public key
     */
    public String getPqcServerPublicKey() {
        return (String) jsonObject.get("pqcServerPublicKey");
    }

    /**
     * Sets PQC server public key
     * @param serverPublicKey Public key as base64
     */
    public void setPqcServerPublicKey(String serverPublicKey) {
        jsonObject.put("pqcServerPublicKey", serverPublicKey);
    }

    /**
     * @return Biometry factor key
     */
    @JsonIgnore
    public SecretKey getBiometryFactorKeyObject() {
        final String biometryFactorKey;
        switch (getVersion().intValue()) {
            case 3 -> biometryFactorKey = (String) jsonObject.get("signatureBiometryKey");
            case 4 -> biometryFactorKey = (String) jsonObject.get("biometryFactorKey");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
        if (biometryFactorKey == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(biometryFactorKey));
    }

    /**
     * Sets biometry factor key object
     * @param biometryFactorKeyObject Biometry factor key object
     */
    @JsonIgnore
    public void setBiometryFactorKeyObject(SecretKey biometryFactorKeyObject) {
        String biometryFactorKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(biometryFactorKeyObject));
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureBiometryKey", biometryFactorKey);
            case 4 -> jsonObject.put("biometryFactorKey", biometryFactorKey);
        }
    }

    /**
     * @return Base64 encoded byte representation of the biometry factor key
     */
    public String getBiometryFactorKey() {
        return switch (getVersion().intValue()) {
            case 3 -> (String) jsonObject.get("signatureBiometryKey");
            case 4 -> (String) jsonObject.get("biometryFactorKey");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        };
    }

    /**
     * Sets biometry factor key
     * @param biometryFactorKey Biometry factor key
     */
    public void setBiometryFactorKey(String biometryFactorKey) {
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureBiometryKey", biometryFactorKey);
            case 4 -> jsonObject.put("biometryFactorKey", biometryFactorKey);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Byte representation of the knowledge factor key
     */
    @JsonIgnore
    public byte[] getKnowledgeFactorKeyEncryptedBytes() {
        String knowledgeFactorKeyEncrypted;
        switch (getVersion().intValue()) {
            case 3 -> knowledgeFactorKeyEncrypted = (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
            case 4 -> knowledgeFactorKeyEncrypted = (String) jsonObject.get("knowledgeFactorKeyEncrypted");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
        return Base64.getDecoder().decode(knowledgeFactorKeyEncrypted);
    }

    /**
     * Sets knowledge factor key encrypted bytes
     * @param knowledgeFactorKeyEncryptedBytes Knowledge factor key encrypted bytes
     */
    @JsonIgnore
    public void setKnowledgeFactorKeyEncryptedBytes(byte[] knowledgeFactorKeyEncryptedBytes) {
        String knowledgeFactorKeyEncrypted = Base64.getEncoder().encodeToString(knowledgeFactorKeyEncryptedBytes);
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureKnowledgeKeyEncrypted", knowledgeFactorKeyEncrypted);
            case 4 -> jsonObject.put("knowledgeFactorKeyEncrypted", knowledgeFactorKeyEncrypted);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Base64 encoded byte representation of the knowledge factor key
     */
    public String getKnowledgeFactorKeyEncrypted() {
        return switch (getVersion().intValue()) {
            case 3 -> (String) jsonObject.get("signatureKnowledgeKeyEncrypted");
            case 4 -> (String) jsonObject.get("knowledgeFactorKeyEncrypted");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        };
    }

    /**
     * Sets knowledge factor key encrypted values
     * @param knowledgeFactorKeyEncrypted Knowledge factor key encrypted value
     */
    public void setKnowledgeFactorKeyEncrypted(String knowledgeFactorKeyEncrypted) {
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureKnowledgeKeyEncrypted", knowledgeFactorKeyEncrypted);
            case 4 -> jsonObject.put("knowledgeFactorKeyEncrypted", knowledgeFactorKeyEncrypted);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Knowledge factor key salt bytes
     */
    @JsonIgnore
    public byte[] getKnowledgeFactorKeySaltBytes() {
        String knowledgeFactorKeySalt;
        switch (getVersion().intValue()) {
            case 3 -> knowledgeFactorKeySalt = (String) jsonObject.get("signatureKnowledgeKeySalt");
            case 4 -> knowledgeFactorKeySalt = (String) jsonObject.get("knowledgeFactorKeySalt");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
        return Base64.getDecoder().decode(knowledgeFactorKeySalt);
    }

    /**
     * Sets knowledge factor key salt bytes
     * @param knowledgeFactorKeySaltBytes Knowledge factor key salt bytes
     */
    @JsonIgnore
    public void setKnowledgeFactorKeySaltBytes(byte[] knowledgeFactorKeySaltBytes) {
        String knowledgeFactorKeySalt = Base64.getEncoder().encodeToString(knowledgeFactorKeySaltBytes);
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureKnowledgeKeySalt", knowledgeFactorKeySalt);
            case 4 -> jsonObject.put("knowledgeFactorKeySalt", knowledgeFactorKeySalt);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Knowledge factor salt
     */
    public String getKnowledgeFactorKeySalt() {
        return switch (getVersion().intValue()) {
            case 3 -> (String) jsonObject.get("signatureKnowledgeKeySalt");
            case 4 -> (String) jsonObject.get("knowledgeFactorKeySalt");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        };
    }

    /**
     * Sets knowledge factor key salt
     * @param knowledgeFactorKeySalt Knowledge factor key salt value
     */
    public void setKnowledgeFactorKeySalt(String knowledgeFactorKeySalt) {
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signatureKnowledgeKeySalt", knowledgeFactorKeySalt);
            case 4 -> jsonObject.put("knowledgeFactorKeySalt", knowledgeFactorKeySalt);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Possession factor key
     */
    @JsonIgnore
    public SecretKey getPossessionFactorKeyObject() {
        final String possessionFactorKey;
        switch (getVersion().intValue()) {
            case 3 -> possessionFactorKey = (String) jsonObject.get("signaturePossessionKey");
            case 4 -> possessionFactorKey = (String) jsonObject.get("possessionFactorKey");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
        if (possessionFactorKey == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(possessionFactorKey));
    }

    /**
     * Sets possession factor key object
     * @param possessionFactorKeyObject Possession factor key object value
     */
    @JsonIgnore
    public void setPossessionFactorKeyObject(SecretKey possessionFactorKeyObject) {
        String possessionFactorKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(possessionFactorKeyObject));
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signaturePossessionKey", possessionFactorKey);
            case 4 -> jsonObject.put("possessionFactorKey", possessionFactorKey);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Base64 encoded byte representation of the possession factor key
     */
    public String getPossessionFactorKey() {
        return switch (getVersion().intValue()) {
            case 3 -> (String) jsonObject.get("signaturePossessionKey");
            case 4 -> (String) jsonObject.get("possessionFactorKey");
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        };
    }

    /**
     * Sets possession factor key
     * @param possessionFactorKey Base64 encoded byte representation of the possession factor key
     */
    public void setPossessionFactorKey(String possessionFactorKey) {
        switch (getVersion().intValue()) {
            case 3 -> jsonObject.put("signaturePossessionKey", possessionFactorKey);
            case 4 -> jsonObject.put("possessionFactorKey", possessionFactorKey);
            default -> throw new IllegalStateException("Unsupported version: " + getVersion());
        }
    }

    /**
     * @return Transport master key object value (V3)
     */
    @JsonIgnore
    public SecretKey getTransportMasterKeyObject() {
        final String transportMasterKey = (String) jsonObject.get("transportMasterKey");
        if (transportMasterKey == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKey));
    }

    /**
     * Sets transport master key object (V3)
     * @param transportMasterKeyObject Transport master key object value
     */
    @JsonIgnore
    public void setTransportMasterKeyObject(SecretKey transportMasterKeyObject) {
        String transportMasterKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(transportMasterKeyObject));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    /**
     * @return Base64 encoded byte representation of the transport master key (V3)
     */
    public String getTransportMasterKey() {
        return (String) jsonObject.get("transportMasterKey");
    }

    /**
     * Sets transport master key value (V3)
     * @param transportMasterKey Base64 encoded byte representation of the transport master key
     */
    public void setTransportMasterKey(String transportMasterKey) {
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    /**
     * @return Shared secret algorithm (V4)
     */
    public String getSharedSecretAlgorithm() {
        return (String) jsonObject.get("sharedSecretAlgorithm");
    }

    /**
     * Sets shared secret algorithm (V4)
     * @param sharedSecretAlgorithm Shared secret algorithm
     */
    public void setSharedSecretAlgorithm(String sharedSecretAlgorithm) {
        jsonObject.put("sharedSecretAlgorithm", sharedSecretAlgorithm);
    }

    /**
     * @return Key for signing payload in getting temporary key request in activation scope (V4)
     */
    @JsonIgnore
    public SecretKey getTemporaryKeyActSignRequestKeyObject() {
        final String temporaryKeyActSignRequestKey = getTemporaryKeyActSignRequestKey();
        if (temporaryKeyActSignRequestKey == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(temporaryKeyActSignRequestKey));
    }

    /**
     * @return Key for signing payload in getting temporary key request in activation scope (V4)
     */
    public String getTemporaryKeyActSignRequestKey() {
        return (String) jsonObject.get("temporaryKeyActSignRequestKey");
    }

    /**
     * Sets key for signing payload in getting temporary key request in activation scope (V4)
     * @param temporaryKeyActSignRequestKey Key for signing payload in getting temporary key request in activation scope
     */
    @JsonIgnore
    public void setTemporaryKeyActSignRequestKeyObject(SecretKey temporaryKeyActSignRequestKey) {
        String temporaryKeyActSignRequestKeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(temporaryKeyActSignRequestKey));
        jsonObject.put("temporaryKeyActSignRequestKey", temporaryKeyActSignRequestKeyBase64);
    }

    /**
     * Sets key for signing payload in getting temporary key request in activation scope (V4)
     * @param temporaryKeyActSignRequestKey Key for signing payload in getting temporary key request in activation scope
     */
    public void setTemporaryKeyActSignRequestKey(String temporaryKeyActSignRequestKey) {
        jsonObject.put("temporaryKeyActSignRequestKey", temporaryKeyActSignRequestKey);
    }

    /**
     * @return Key for for verifying MAC for status blob (V4)
     */
    @JsonIgnore
    public SecretKey getStatusBlobMacKeyObject() {
        final String statusBlobMacKey = getStatusBlobMacKey();
        if (statusBlobMacKey == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(statusBlobMacKey));
    }

    /**
     * @return Key for verifying MAC for status blob (V4)
     */
    public String getStatusBlobMacKey() {
        return (String) jsonObject.get("statusBlobMacKey");
    }

    /**
     * Sets key for verifying MAC for status blob
     * @param statusBlobMacKey Key for verifying MAC for status blob
     */
    @JsonIgnore
    public void setStatusBlobMacKeyObject(SecretKey statusBlobMacKey) {
        String statusBlobMacKeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(statusBlobMacKey));
        jsonObject.put("statusBlobMacKey", statusBlobMacKeyBase64);
    }

    /**
     * Sets key for verifying MAC for status blob
     * @param statusBlobMacKey Key for key for verifying MAC for status blob
     */
    public void setStatusBlobMacKey(String statusBlobMacKey) {
        jsonObject.put("statusBlobMacKey", statusBlobMacKey);
    }

    /**
     * @return Key for sharedInfo2 calculation for end-to-end encryption (V4)
     */
    @JsonIgnore
    public SecretKey getSharedInfo2KeyObject() {
        final String sharedInfo2Key = getSharedInfo2Key();
        if (sharedInfo2Key == null) {
            return null;
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(sharedInfo2Key));
    }

    /**
     * @return Key for sharedInfo2 calculation for end-to-end encryption (V4)
     */
    public String getSharedInfo2Key() {
        return (String) jsonObject.get("sharedInfo2Key");
    }

    /**
     * Sets key for sharedInfo2 calculation for end-to-end encryption (V4)
     * @param sharedInfo2Key Key for sharedInfo2 calculation for end-to-end encryption
     */
    @JsonIgnore
    public void setSharedInfo2KeyObject(SecretKey sharedInfo2Key) {
        String sharedInfo2KeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(sharedInfo2Key));
        jsonObject.put("sharedInfo2Key", sharedInfo2KeyBase64);
    }

    /**
     * Sets key for sharedInfo2 calculation for end-to-end encryption (V4)
     * @param sharedInfo2Key Key for sharedInfo2 calculation for end-to-end encryption
     */
    public void setSharedInfo2Key(String sharedInfo2Key) {
        jsonObject.put("sharedInfo2Key", sharedInfo2Key);
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
