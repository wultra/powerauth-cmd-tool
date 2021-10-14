/*
 * PowerAuth Command-line utility
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
package io.getlime.security.powerauth.lib.cmd.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Helper class with security utilities.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class SecurityUtil {

    /**
     * ECIES factory
     */
    private static final EciesFactory ECIES_FACTORY = new EciesFactory();

    /**
     * Key convertor
     */
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Creates new encryptor
     *
     * @param applicationSecretValue Application secret value
     * @param resultStatusObject Activation status object
     * @param sharedInfo Shared info parameter value
     *
     * @return New encryptor instance
     * @throws CryptoProviderException when an error during encryptor preparation occurred
     * @throws GenericCryptoException when an error during encryptor preparation occurred
     * @throws InvalidKeySpecException when an error during server public key processing occurred
     */
    public static EciesEncryptor createEncryptor(String applicationSecretValue,
                                                 ResultStatusObject resultStatusObject,
                                                 EciesSharedInfo1 sharedInfo)
            throws CryptoProviderException, GenericCryptoException, InvalidKeySpecException {
        byte[] applicationSecret = applicationSecretValue.getBytes(StandardCharsets.UTF_8);
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(resultStatusObject.getServerPublicKey());
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(resultStatusObject.getTransportMasterKey());
        final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        return ECIES_FACTORY.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, sharedInfo);
    }

    /**
     * Encrypts an object using the provided encryptor
     * <p>The object will be serialized to json and the json bytes will be then encrypted</p>
     *
     * @param encryptor Encyptor instance
     * @param value Object value to be encrypted
     * @param useIv True for encryption with non-zero initialization vector
     *
     * @return Cryptogram value of the provided object.
     * @throws EciesException when an error during object encryption occurred
     * @throws IOException when an error during object encryption occurred
     */
    public static EciesCryptogram encryptObject(EciesEncryptor encryptor, Object value, boolean useIv)
            throws EciesException, IOException {
        ByteArrayOutputStream baosL = new ByteArrayOutputStream();
        RestClientConfiguration.defaultMapper().writeValue(baosL, value);
        return encryptor.encryptRequest(baosL.toByteArray(), useIv);
    }

    /**
     * Decrypts bytes from a response
     *
     * @param encryptor Encryptor
     * @param encryptedResponse Encrypted response
     * @return decrypted bytes
     * @throws EciesException when an error during decryption occurred
     */
    public static byte[] decryptBytesFromResponse(EciesEncryptor encryptor, EciesEncryptedResponse encryptedResponse)
            throws EciesException {
        byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
        byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
        final EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

        return encryptor.decryptResponse(eciesCryptogramResponse);
    }

    /**
     * Creates an encrypted request instance
     *
     * @param eciesCryptogram Cryptogram data to be sent
     * @param useIv True for encryption with non-zero initialization vector
     * @return Encrypted request instance
     */
    public static EciesEncryptedRequest createEncryptedRequest(EciesCryptogram eciesCryptogram, boolean useIv) {
        EciesEncryptedRequest request = new EciesEncryptedRequest();
        request.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        request.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        request.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));
        request.setNonce(useIv ? BaseEncoding.base64().encode(eciesCryptogram.getNonce()) : null);
        return request;
    }

}
