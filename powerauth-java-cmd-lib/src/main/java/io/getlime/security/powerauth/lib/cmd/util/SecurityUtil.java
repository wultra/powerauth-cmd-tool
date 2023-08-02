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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

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
     * @param associatedData Associated data for ECIES.
     * @param version Protocol version.
     *
     * @return New encryptor instance
     * @throws CryptoProviderException when an error during encryptor preparation occurred
     * @throws GenericCryptoException when an error during encryptor preparation occurred
     * @throws InvalidKeySpecException when an error during server public key processing occurred
     * @throws EciesException when an encryption error occurs
     */
    public static EciesEncryptor createEncryptor(String applicationSecretValue,
                                                 ResultStatusObject resultStatusObject,
                                                 EciesSharedInfo1 sharedInfo,
                                                 PowerAuthVersion version,
                                                 byte[] associatedData)
            throws CryptoProviderException, GenericCryptoException, InvalidKeySpecException, EciesException {
        final byte[] applicationSecret = applicationSecretValue.getBytes(StandardCharsets.UTF_8);
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(resultStatusObject.getServerPublicKey());
        final byte[] transportMasterKeyBytes = Base64.getDecoder().decode(resultStatusObject.getTransportMasterKey());
        final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        final Long timestamp = version.useTimestamp() ? new Date().getTime() : null;
        final byte[] nonceBytes = version.useIv() ? new KeyGenerator().generateRandomBytes(16) : null;
        final EciesParameters parameters = EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();
        return ECIES_FACTORY.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, sharedInfo, parameters);
    }

    /**
     * Encrypts an object using the provided encryptor
     * <p>The object will be serialized to json and the json bytes will be then encrypted</p>
     *
     * @param encryptor Encyptor instance
     * @param value Object value to be encrypted
     * @param useIv True for encryption with non-zero initialization vector
     * @param useTimestamp True when timestamp is used
     * @param associatedData Data associated with ECIES request
     * @return Cryptogram value of the provided object.
     * @throws EciesException when an error during object encryption occurred
     * @throws IOException when an error during object encryption occurred
     */
    public static EciesPayload encryptObject(EciesEncryptor encryptor, Object value, boolean useIv, boolean useTimestamp, byte[] associatedData)
            throws EciesException, IOException {
        ByteArrayOutputStream baosL = new ByteArrayOutputStream();
        RestClientConfiguration.defaultMapper().writeValue(baosL, value);
        return encryptor.encrypt(baosL.toByteArray(), useIv, useTimestamp, associatedData);
    }

    /**
     * Decrypts bytes from a response
     *
     * @param decryptor Decryptor
     * @param encryptedResponse Encrypted response
     * @param associatedData Associated data for ECIES
     * @return decrypted bytes
     * @throws EciesException when an error during decryption occurred
     */
    public static byte[] decryptBytesFromResponse(EciesDecryptor decryptor, EciesEncryptedResponse encryptedResponse, byte[] associatedData)
            throws EciesException {

        final byte[] ephemeralPublicKey = decryptor.getEnvelopeKey().getEphemeralKeyPublic();
        final byte[] mac = Base64.getDecoder().decode(encryptedResponse.getMac());
        final byte[] encryptedData = Base64.getDecoder().decode(encryptedResponse.getEncryptedData());
        final byte[] nonce = encryptedResponse.getNonce() != null ? Base64.getDecoder().decode(encryptedResponse.getNonce()) : null;
        final Long timestamp = encryptedResponse.getTimestamp();
        final EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData);

        final EciesParameters parameters = new EciesParameters(nonce, associatedData, timestamp);
        final EciesPayload payload = new EciesPayload(eciesCryptogramResponse, parameters);

        return decryptor.decrypt(payload);
    }

    /**
     * Creates an encrypted request instance
     *
     * @param eciesPayload Ecies payload data to be sent
     * @param useIv True for encryption with non-zero initialization vector
     * @param useTimestamp True when timestamp is present
     * @return Encrypted request instance
     */
    public static EciesEncryptedRequest createEncryptedRequest(EciesPayload eciesPayload, boolean useIv, boolean useTimestamp) {
        EciesEncryptedRequest request = new EciesEncryptedRequest();
        request.setEncryptedData(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEncryptedData()));
        request.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEphemeralPublicKey()));
        request.setMac(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getMac()));
        request.setNonce(useIv ? Base64.getEncoder().encodeToString(eciesPayload.getParameters().getNonce()) : null);
        request.setTimestamp(useTimestamp ? new Date().getTime() : null);
        return request;
    }

}
