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
import lombok.*;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicLong;

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
    private JSONObject jsonObject = new JSONObject();

    private String activationId;

    private AtomicLong counter = new AtomicLong();

    private String ctrDataBase;

    @JsonIgnore
    private byte[] encryptedDevicePrivateKeyBytes;

    @Setter(AccessLevel.NONE)
    private String encryptedDevicePrivateKey;

    @JsonIgnore
    private PublicKey serverPublicKeyObject;

    @Setter(AccessLevel.NONE)
    private String serverPublicKey;

    @JsonIgnore
    private SecretKey signatureBiometryKeyObject;

    @Setter(AccessLevel.NONE)
    private String signatureBiometryKey;

    @JsonIgnore
    private byte[] signatureKnowledgeKeyEncryptedBytes;

    @Setter(AccessLevel.NONE)
    private String signatureKnowledgeKeyEncrypted;

    @JsonIgnore
    private byte[] signatureKnowledgeKeySaltBytes;

    @Setter(AccessLevel.NONE)
    private String signatureKnowledgeKeySalt;

    @JsonIgnore
    private SecretKey signaturePossessionKeyObject;

    @Setter(AccessLevel.NONE)
    private String signaturePossessionKey;

    private String responseData;

    @JsonIgnore
    private SecretKey transportMasterKeyObject;

    @Setter(AccessLevel.NONE)
    private String transportMasterKey;

    private Long version;

    public void setActivationId(String activationId) {
        this.activationId = activationId;
        jsonObject.put("activationId", activationId);
    }

    public void setCounter(AtomicLong counter) {
        this.counter = counter;
        jsonObject.put("counter", counter);
    }

    public void setCtrDataBase(String ctrDataBase) {
        this.ctrDataBase = ctrDataBase;
        jsonObject.put("ctrDataBase", ctrDataBase);
    }

    public void setEncryptedDevicePrivateKeyBytes(byte[] encryptedDevicePrivateKeyBytes) {
        this.encryptedDevicePrivateKeyBytes = encryptedDevicePrivateKeyBytes;
        this.encryptedDevicePrivateKey = BaseEncoding.base64().encode(encryptedDevicePrivateKeyBytes);
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    public void setEncryptedDevicePrivateKey(String encryptedDevicePrivateKey) {
        this.encryptedDevicePrivateKey = encryptedDevicePrivateKey;
        this.encryptedDevicePrivateKeyBytes = BaseEncoding.base64().decode(encryptedDevicePrivateKey);
        jsonObject.put("encryptedDevicePrivateKey", encryptedDevicePrivateKey);
    }

    public void setResponseData(String responseData) {
        this.responseData = responseData;
        jsonObject.put("responseData", responseData);
    }

    public void setServerPublicKeyObject(PublicKey serverPublicKeyObject) throws Exception {
        this.serverPublicKeyObject = serverPublicKeyObject;
        this.serverPublicKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertPublicKeyToBytes(serverPublicKeyObject));
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    public void setServerPublicKey(String serverPublicKey) throws Exception {
        this.serverPublicKey = serverPublicKey;
        this.serverPublicKeyObject = KEY_CONVERTOR.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKey));
        jsonObject.put("serverPublicKey", serverPublicKey);
    }

    public void setSignatureBiometryKeyObject(SecretKey signatureBiometryKeyObject) {
        this.signatureBiometryKeyObject = signatureBiometryKeyObject;
        this.signatureBiometryKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signatureBiometryKeyObject));
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    public void setSignatureBiometryKey(String signatureBiometryKey) {
        this.signatureBiometryKey = signatureBiometryKey;
        this.signatureBiometryKeyObject = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signatureBiometryKey));
        jsonObject.put("signatureBiometryKey", signatureBiometryKey);
    }

    public void setSignatureKnowledgeKeyEncryptedBytes(byte[] signatureKnowledgeKeyEncryptedBytes) {
        this.signatureKnowledgeKeyEncryptedBytes = signatureKnowledgeKeyEncryptedBytes;
        this.signatureKnowledgeKeyEncrypted = BaseEncoding.base64().encode(signatureKnowledgeKeyEncryptedBytes);
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    public void setSignatureKnowledgeKeyEncrypted(String signatureKnowledgeKeyEncrypted) {
        this.signatureKnowledgeKeyEncrypted = signatureKnowledgeKeyEncrypted;
        this.signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(signatureKnowledgeKeyEncrypted);
        jsonObject.put("signatureKnowledgeKeyEncrypted", signatureKnowledgeKeyEncrypted);
    }

    public void setSignatureKnowledgeKeySaltBytes(byte[] signatureKnowledgeKeySaltBytes) {
        this.signatureKnowledgeKeySaltBytes = signatureKnowledgeKeySaltBytes;
        this.signatureKnowledgeKeySalt = BaseEncoding.base64().encode(signatureKnowledgeKeySaltBytes);
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    public void setSignatureKnowledgeKeySalt(String signatureKnowledgeKeySalt) {
        this.signatureKnowledgeKeySalt = signatureKnowledgeKeySalt;
        this.signatureKnowledgeKeySaltBytes = BaseEncoding.base64().decode(signatureKnowledgeKeySalt);
        jsonObject.put("signatureKnowledgeKeySalt", signatureKnowledgeKeySalt);
    }

    public void setSignaturePossessionKeyObject(SecretKey signaturePossessionKeyObject) {
        this.signaturePossessionKeyObject = signaturePossessionKeyObject;
        this.signaturePossessionKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signaturePossessionKeyObject));
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    public void setSignaturePossessionKey(String signaturePossessionKey) {
        this.signaturePossessionKey = signaturePossessionKey;
        this.signaturePossessionKeyObject = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signaturePossessionKey));
        jsonObject.put("signaturePossessionKey", signaturePossessionKey);
    }

    public void setTransportMasterKeyObject(SecretKey transportMasterKeyObject) {
        this.transportMasterKeyObject = transportMasterKeyObject;
        this.transportMasterKey = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKeyObject));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    public void setTransportMasterKey(String transportMasterKey) {
        this.transportMasterKey = transportMasterKey;
        this.transportMasterKeyObject = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKey));
        jsonObject.put("transportMasterKey", transportMasterKey);
    }

    public void setVersion(Long version) {
        this.version = version;
        jsonObject.put("version", version);
    }

    public JSONObject toJsonObject() {
        return jsonObject;
    }

}
