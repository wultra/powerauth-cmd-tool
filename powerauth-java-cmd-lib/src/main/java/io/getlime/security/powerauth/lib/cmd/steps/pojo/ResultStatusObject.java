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

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data @NoArgsConstructor @AllArgsConstructor
public class ResultStatusObject {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private String activationId;

    private AtomicLong counter = new AtomicLong();

    private String ctrDataBase64;

    @JsonIgnore
    private byte[] encryptedDevicePrivateKey;

    @Setter(AccessLevel.NONE)
    private String encryptedDevicePrivateKeyBase64;

    @JsonIgnore
    private PublicKey serverPublicKey;

    @Setter(AccessLevel.NONE)
    private String serverPublicKeyBase64;

    @JsonIgnore
    private SecretKey signatureBiometryKey;

    @Setter(AccessLevel.NONE)
    private String signatureBiometryKeyBase64;

    @JsonIgnore
    private byte[] signatureKnowledgeKeyEncrypted;

    @Setter(AccessLevel.NONE)
    private String signatureKnowledgeKeyEncryptedBase64;

    @JsonIgnore
    private byte[] signatureKnowledgeKeySalt;

    @Setter(AccessLevel.NONE)
    private String signatureKnowledgeKeySaltBase64;

    @JsonIgnore
    private SecretKey signaturePossessionKey;

    @Setter(AccessLevel.NONE)
    private String signaturePossessionKeyBase64;

    private String responseData;

    @JsonIgnore
    private SecretKey transportMasterKey;

    @Setter(AccessLevel.NONE)
    private String transportMasterKeyBase64;

    private Long version;

    public void setEncryptedDevicePrivateKey(byte[] encryptedDevicePrivateKey) {
        this.encryptedDevicePrivateKey = encryptedDevicePrivateKey;
        this.encryptedDevicePrivateKeyBase64 = BaseEncoding.base64().encode(encryptedDevicePrivateKey);
    }

    public void setEncryptedDevicePrivateKeyBase64(String encryptedDevicePrivateKeyBase64) {
        this.encryptedDevicePrivateKeyBase64 = encryptedDevicePrivateKeyBase64;
        this.encryptedDevicePrivateKey = BaseEncoding.base64().decode(encryptedDevicePrivateKeyBase64);
    }

    public void setServerPublicKey(PublicKey serverPublicKey) throws Exception {
        this.serverPublicKey = serverPublicKey;
        this.serverPublicKeyBase64 = BaseEncoding.base64().encode(KEY_CONVERTOR.convertPublicKeyToBytes(serverPublicKey));
    }

    public void setServerPublicKeyBase64(String serverPublicKeyBase64) throws Exception {
        this.serverPublicKeyBase64 = serverPublicKeyBase64;
        this.serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));
    }

    public void setSignatureBiometryKey(SecretKey signatureBiometryKey) {
        this.signatureBiometryKey = signatureBiometryKey;
        this.signatureBiometryKeyBase64 = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signatureBiometryKey));
    }

    public void setSignatureBiometryKeyBase64(String signatureBiometryKeyBase64) {
        this.signatureBiometryKeyBase64 = signatureBiometryKeyBase64;
        this.signatureBiometryKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signatureBiometryKeyBase64));
    }

    public void setSignatureKnowledgeKeyEncrypted(byte[] signatureKnowledgeKeyEncrypted) {
        this.signatureKnowledgeKeyEncrypted = signatureKnowledgeKeyEncrypted;
        this.signatureKnowledgeKeyEncryptedBase64 = BaseEncoding.base64().encode(signatureKnowledgeKeyEncrypted);
    }

    public void setSignatureKnowledgeKeyEncryptedBase64(String signatureKnowledgeKeyEncryptedBase64) {
        this.signatureKnowledgeKeyEncryptedBase64 = signatureKnowledgeKeyEncryptedBase64;
        this.signatureKnowledgeKeyEncrypted = BaseEncoding.base64().decode(signatureKnowledgeKeyEncryptedBase64);
    }

    public void setSignatureKnowledgeKeySalt(byte[] signatureKnowledgeKeySalt) {
        this.signatureKnowledgeKeySalt = signatureKnowledgeKeySalt;
        this.signatureKnowledgeKeySaltBase64 = BaseEncoding.base64().encode(signatureKnowledgeKeySalt);
    }

    public void setSignatureKnowledgeKeySaltBase64(String signatureKnowledgeKeySaltBase64) {
        this.signatureKnowledgeKeySaltBase64 = signatureKnowledgeKeySaltBase64;
        this.signatureKnowledgeKeySalt = BaseEncoding.base64().decode(signatureKnowledgeKeySaltBase64);
    }

    public void setSignaturePossessionKey(SecretKey signaturePossessionKey) {
        this.signaturePossessionKey = signaturePossessionKey;
        this.signaturePossessionKeyBase64 = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(signaturePossessionKey));
    }

    public void setSignaturePossessionKeyBase64(String signaturePossessionKeyBase64) {
        this.signaturePossessionKeyBase64 = signaturePossessionKeyBase64;
        this.signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(signaturePossessionKeyBase64));
    }

    public void setTransportMasterKey(SecretKey transportMasterKey) {
        this.transportMasterKey = transportMasterKey;
        this.transportMasterKeyBase64 = BaseEncoding.base64().encode(KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKey));
    }

    public void setTransportMasterKeyBase64(String transportMasterKeyBase64) {
        this.transportMasterKeyBase64 = transportMasterKeyBase64;
        this.transportMasterKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKeyBase64));
    }

}
