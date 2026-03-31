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
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;

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
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    /**
     * Backward compatibility, sync all modifications to the JSON object
     */
    @JsonIgnore
    private JSONObject jsonObject = new JSONObject(new LinkedHashMap<>());

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
     * @return Byte representation of the encrypted EC device private key
     */
    @JsonIgnore
    public byte[] getEncryptedEcDevicePrivateKeyBytes() {
        final String encryptedEcDevicePrivateKey = getEncryptedEcDevicePrivateKey();
        if (encryptedEcDevicePrivateKey == null) {
            throw new IllegalStateException("Encrypted EC device private key is missing.");
        }
        return Base64.getDecoder().decode(encryptedEcDevicePrivateKey);
    }

    /**
     * Sets encrypted EC device private key
     * @param encryptedDevicePrivateKeyBytes Encrypted EC device private key bytes
     */
    @JsonIgnore
    public void setEncryptedEcDevicePrivateKeyBytes(byte[] encryptedDevicePrivateKeyBytes) {
        final String encryptedDevicePrivateKey = Base64.getEncoder().encodeToString(encryptedDevicePrivateKeyBytes);
        jsonObject.put("encryptedEcDevicePrivateKey", encryptedDevicePrivateKey);
    }

    /**
     * @return Base64 encoded byte representation of the encrypted EC device private key
     */
    public String getEncryptedEcDevicePrivateKey() {
        return (String) jsonObject.get("encryptedEcDevicePrivateKey");
    }

    /**
     * Sets encrypted EC device private key object
     * @param encryptedDevicePrivateKey Encrypted EC device private key object
     */
    public void setEncryptedEcDevicePrivateKey(String encryptedDevicePrivateKey) {
        jsonObject.put("encryptedEcDevicePrivateKey", encryptedDevicePrivateKey);
    }

    /**
     * @return Byte representation of the encrypted PQC device private key
     */
    @JsonIgnore
    public byte[] getEncryptedPqcDevicePrivateKeyBytes() {
        final String encryptedPqcDevicePrivateKey = getEncryptedPqcDevicePrivateKey();
        if (encryptedPqcDevicePrivateKey == null) {
            throw new IllegalStateException("Encrypted PQC device private key is missing.");
        }
        return Base64.getDecoder().decode(encryptedPqcDevicePrivateKey);
    }

    /**
     * Sets encrypted PQC device private key
     * @param encryptedDevicePrivateKeyBytes Encrypted PQC device private key bytes
     */
    @JsonIgnore
    public void setEncryptedPqcDevicePrivateKeyBytes(byte[] encryptedDevicePrivateKeyBytes) {
        final String encryptedDevicePrivateKey = Base64.getEncoder().encodeToString(encryptedDevicePrivateKeyBytes);
        jsonObject.put("encryptedPqcDevicePrivateKey", encryptedDevicePrivateKey);
    }

    /**
     * @return Base64 encoded byte representation of the encrypted EC device private key
     */
    public String getEncryptedPqcDevicePrivateKey() {
        return (String) jsonObject.get("encryptedPqcDevicePrivateKey");
    }

    /**
     * Sets encrypted PQC device private key
     * @param encryptedDevicePrivateKey Encrypted PQC device private key
     */
    public void setEncryptedPqcDevicePrivateKey(String encryptedDevicePrivateKey) {
        jsonObject.put("encryptedPqcDevicePrivateKey", encryptedDevicePrivateKey);
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
        final String ecServerPublicKey = getEcServerPublicKey();
        if (ecServerPublicKey == null) {
            throw new IllegalStateException("EC server public key is missing.");
        }
        return KEY_CONVERTOR_EC.convertBytesToPublicKey(resolveEcCurve(), Base64.getDecoder().decode(ecServerPublicKey));
    }

    /**
     * Sets EC server public key object
     * @param serverPublicKeyObject Public key object
     * @throws CryptoProviderException when the public key cannot be encoded
     * @throws GenericCryptoException when the public key conversion fails
     */
    @JsonIgnore
    public void setEcServerPublicKeyObject(PublicKey serverPublicKeyObject) throws CryptoProviderException, GenericCryptoException {
        final String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(resolveEcCurve(), serverPublicKeyObject));
        jsonObject.put("ecServerPublicKey", serverPublicKey);
    }

    /**
     * @return Base64 encoded byte representation of the EC server public key
     */
    public String getEcServerPublicKey() {
        return (String) jsonObject.get("ecServerPublicKey");
    }

    /**
     * Sets EC server public key
     * @param serverPublicKey Public key as base64
     */
    public void setEcServerPublicKey(String serverPublicKey) {
        jsonObject.put("ecServerPublicKey", serverPublicKey);
    }

    /**
     * @return Server PQC public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getPqcServerPublicKeyObject() throws Exception {
        final String pqcServerPublicKey = getPqcServerPublicKey();
        if (pqcServerPublicKey == null) {
            throw new IllegalStateException("PQC server public key is missing.");
        }
        return KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(Base64.getDecoder().decode(pqcServerPublicKey));
    }

    /**
     * Sets PQC server public key object
     * @param serverPublicKeyObject Public key object
     * @throws Exception when the public key cannot be encoded
     */
    @JsonIgnore
    public void setPqcServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        final String serverPublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(serverPublicKeyObject));
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
     * @return Device EC public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getEcDevicePublicKeyObject() throws Exception {
        final String ecDevicePublicKey = getEcDevicePublicKey();
        if (ecDevicePublicKey == null) {
            throw new IllegalStateException("EC device public key is missing.");
        }
        return KEY_CONVERTOR_EC.convertBytesToPublicKey(resolveEcCurve(), Base64.getDecoder().decode(ecDevicePublicKey));
    }

    /**
     * Sets EC device public key object
     * @param devicePublicKeyObject Public key object
     * @throws CryptoProviderException when the public key cannot be encoded
     * @throws GenericCryptoException when the public key conversion fails
     */
    @JsonIgnore
    public void setEcDevicePublicKeyObject(PublicKey devicePublicKeyObject) throws CryptoProviderException, GenericCryptoException {
        final String devicePublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(resolveEcCurve(), devicePublicKeyObject));
        jsonObject.put("ecDevicePublicKey", devicePublicKey);
    }

    /**
     * @return Base64 encoded byte representation of the EC device public key
     */
    public String getEcDevicePublicKey() {
        return (String) jsonObject.get("ecDevicePublicKey");
    }

    /**
     * Sets EC device public key
     * @param devicePublicKey Public key as base64
     */
    public void setEcDevicePublicKey(String devicePublicKey) {
        jsonObject.put("ecDevicePublicKey", devicePublicKey);
    }

    /**
     * @return Device PQC public key
     * @throws Exception when the public key cannot be decoded
     */
    @JsonIgnore
    public PublicKey getPqcDevicePublicKeyObject() throws Exception {
        final String pqcDevicePublicKey = getPqcDevicePublicKey();
        if (pqcDevicePublicKey == null) {
            throw new IllegalStateException("PQC device public key is missing.");
        }
        return KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(Base64.getDecoder().decode(pqcDevicePublicKey));
    }

    /**
     * Sets PQC device public key object
     * @param devicePublicKeyObject Public key object
     * @throws GenericCryptoException when the public key cannot be encoded
     */
    @JsonIgnore
    public void setPqcDevicePublicKeyObject(PublicKey devicePublicKeyObject) throws GenericCryptoException {
        final String devicePublicKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(devicePublicKeyObject));
        jsonObject.put("pqcDevicePublicKey", devicePublicKey);
    }

    /**
     * @return Base64 encoded byte representation of the PQC device public key
     */
    public String getPqcDevicePublicKey() {
        return (String) jsonObject.get("pqcDevicePublicKey");
    }

    /**
     * Sets PQC device public key
     * @param devicePublicKey Public key as base64
     */
    public void setPqcDevicePublicKey(String devicePublicKey) {
        jsonObject.put("pqcDevicePublicKey", devicePublicKey);
    }

    /**
     * @return Biometry factor key
     */
    @JsonIgnore
    public SecretKey getBiometryFactorKeyObject() {
        final String biometryFactorKey = getBiometryFactorKey();
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
        final String biometryFactorKey = biometryFactorKeyObject != null
                ? Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(biometryFactorKeyObject))
                : null;
        jsonObject.put("biometryFactorKey", biometryFactorKey);
    }

    /**
     * @return Base64 encoded byte representation of the biometry factor key
     */
    public String getBiometryFactorKey() {
        return (String) jsonObject.get("biometryFactorKey");
    }

    /**
     * Sets biometry factor key
     * @param biometryFactorKey Biometry factor key
     */
    public void setBiometryFactorKey(String biometryFactorKey) {
        jsonObject.put("biometryFactorKey", biometryFactorKey);
    }

    /**
     * @return Byte representation of the knowledge factor key
     */
    @JsonIgnore
    public byte[] getKnowledgeFactorKeyEncryptedBytes() {
        final String knowledgeFactorKeyEncrypted = getKnowledgeFactorKeyEncrypted();
        if (knowledgeFactorKeyEncrypted == null) {
            throw new IllegalStateException("Encrypted knowledge factor key is missing.");
        }
        return Base64.getDecoder().decode(knowledgeFactorKeyEncrypted);
    }

    /**
     * Sets knowledge factor key encrypted bytes
     * @param knowledgeFactorKeyEncryptedBytes Knowledge factor key encrypted bytes
     */
    @JsonIgnore
    public void setKnowledgeFactorKeyEncryptedBytes(byte[] knowledgeFactorKeyEncryptedBytes) {
        final String knowledgeFactorKeyEncrypted = Base64.getEncoder().encodeToString(knowledgeFactorKeyEncryptedBytes);
        jsonObject.put("knowledgeFactorKeyEncrypted", knowledgeFactorKeyEncrypted);
    }

    /**
     * @return Base64 encoded byte representation of the knowledge factor key
     */
    public String getKnowledgeFactorKeyEncrypted() {
        return (String) jsonObject.get("knowledgeFactorKeyEncrypted");
    }

    /**
     * Sets knowledge factor key encrypted values
     * @param knowledgeFactorKeyEncrypted Knowledge factor key encrypted value
     */
    public void setKnowledgeFactorKeyEncrypted(String knowledgeFactorKeyEncrypted) {
        jsonObject.put("knowledgeFactorKeyEncrypted", knowledgeFactorKeyEncrypted);
    }

    /**
     * @return Knowledge factor key salt bytes
     */
    @JsonIgnore
    public byte[] getKnowledgeFactorKeySaltBytes() {
        final String knowledgeFactorKeySalt = getKnowledgeFactorKeySalt();
        if (knowledgeFactorKeySalt == null) {
            throw new IllegalStateException("Knowledge factor key salt is missing.");
        }
        return Base64.getDecoder().decode(knowledgeFactorKeySalt);
    }

    /**
     * Sets knowledge factor key salt bytes
     * @param knowledgeFactorKeySaltBytes Knowledge factor key salt bytes
     */
    @JsonIgnore
    public void setKnowledgeFactorKeySaltBytes(byte[] knowledgeFactorKeySaltBytes) {
        final String knowledgeFactorKeySalt = Base64.getEncoder().encodeToString(knowledgeFactorKeySaltBytes);
        jsonObject.put("knowledgeFactorKeySalt", knowledgeFactorKeySalt);
    }

    /**
     * @return Knowledge factor salt
     */
    public String getKnowledgeFactorKeySalt() {
        return (String) jsonObject.get("knowledgeFactorKeySalt");
    }

    /**
     * Sets knowledge factor key salt
     * @param knowledgeFactorKeySalt Knowledge factor key salt value
     */
    public void setKnowledgeFactorKeySalt(String knowledgeFactorKeySalt) {
        jsonObject.put("knowledgeFactorKeySalt", knowledgeFactorKeySalt);
    }

    /**
     * @return Possession factor key
     */
    @JsonIgnore
    public SecretKey getPossessionFactorKeyObject() {
        final String possessionFactorKey = getPossessionFactorKey();
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(possessionFactorKey));
    }

    /**
     * Sets possession factor key object
     * @param possessionFactorKeyObject Possession factor key object value
     */
    @JsonIgnore
    public void setPossessionFactorKeyObject(SecretKey possessionFactorKeyObject) {
        final String possessionFactorKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(possessionFactorKeyObject));
        if (possessionFactorKey == null) {
            throw new IllegalStateException("Possession factor key is missing.");
        }
        jsonObject.put("possessionFactorKey", possessionFactorKey);
    }

    /**
     * @return Base64 encoded byte representation of the possession factor key
     */
    public String getPossessionFactorKey() {
        return (String) jsonObject.get("possessionFactorKey");
    }

    /**
     * Sets possession factor key
     * @param possessionFactorKey Base64 encoded byte representation of the possession factor key
     */
    public void setPossessionFactorKey(String possessionFactorKey) {
        jsonObject.put("possessionFactorKey", possessionFactorKey);
    }

    /**
     * @return Transport master key object value (V3)
     */
    @JsonIgnore
    public SecretKey getTransportMasterKeyObject() {
        final String transportMasterKey = getTransportMasterKey();
        if (transportMasterKey == null) {
            throw new IllegalStateException("Transport master key is missing.");
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKey));
    }

    /**
     * Sets transport master key object (V3)
     * @param transportMasterKeyObject Transport master key object value
     */
    @JsonIgnore
    public void setTransportMasterKeyObject(SecretKey transportMasterKeyObject) {
        final String transportMasterKey = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(transportMasterKeyObject));
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
            throw new IllegalStateException("Temporary key signing key is missing.");
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
        final String temporaryKeyActSignRequestKeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(temporaryKeyActSignRequestKey));
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
     * @return Key for verifying MAC for status blob (V4)
     */
    @JsonIgnore
    public SecretKey getStatusBlobMacKeyObject() {
        final String statusBlobMacKey = getStatusBlobMacKey();
        if (statusBlobMacKey == null) {
            throw new IllegalStateException("Status blob MAC key is missing.");
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
        final String statusBlobMacKeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(statusBlobMacKey));
        jsonObject.put("statusBlobMacKey", statusBlobMacKeyBase64);
    }

    /**
     * Sets key for verifying MAC for status blob
     * @param statusBlobMacKey Key for verifying MAC for status blob
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
            throw new IllegalStateException("SharedInfo2 key is missing.");
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
        final String sharedInfo2KeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(sharedInfo2Key));
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
     * @return Key for personalized data used in offline code MAC (V4)
     */
    @JsonIgnore
    public SecretKey getMacPersonalizedDataKeyObject() {
        final String macPersonalizedDataKey = getMacPersonalizedDataKey();
        if (macPersonalizedDataKey == null) {
            throw new IllegalStateException("Offline personalized data MAC key is missing.");
        }
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(Base64.getDecoder().decode(macPersonalizedDataKey));
    }

    /**
     * @return Key for personalized data used in offline code MAC (V4)
     */
    public String getMacPersonalizedDataKey() {
        return (String) jsonObject.get("macPersonalizedDataKey");
    }

    /**
     * Sets key for personalized data used in offline code MAC (V4)
     * @param macPersonalizedDataKey Key for personalized data used in offline code MAC
     */
    @JsonIgnore
    public void setMacPersonalizedDataKeyObject(SecretKey macPersonalizedDataKey) {
        final String macPersonalizedDataKeyBase64 = Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(macPersonalizedDataKey));
        jsonObject.put("macPersonalizedDataKey", macPersonalizedDataKeyBase64);
    }

    /**
     * Sets key for personalized data used in offline code MAC (V4)
     * @param macPersonalizedDataKey Key for personalized data used in offline code MAC
     */
    public void setMacPersonalizedDataKey(String macPersonalizedDataKey) {
        jsonObject.put("macPersonalizedDataKey", macPersonalizedDataKey);
    }

    /**
     * @return Used PowerAuth version
     */
    public Long getVersion() {
        Long version = (Long) jsonObject.get("version");
        if (version == null) {
            // Existing V3 result status may not have the version set yet
            version = 3L;
        }
        return version;
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

    private EcCurve resolveEcCurve() {
        return getVersion().intValue() == 3 ? EcCurve.P256 : EcCurve.P384;
    }

}
