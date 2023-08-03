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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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
     * @param parameters ECIES parameters.
     *
     * @return New encryptor instance
     * @throws CryptoProviderException when an error during encryptor preparation occurred
     * @throws GenericCryptoException when an error during encryptor preparation occurred
     * @throws InvalidKeySpecException when an error during server public key processing occurred
     * @throws EciesException when an encryption error occurs
     */
    public static EciesEncryptor createEncryptorForActivationScope(String applicationSecretValue,
                                                                   ResultStatusObject resultStatusObject,
                                                                   EciesSharedInfo1 sharedInfo,
                                                                   EciesParameters parameters)
            throws CryptoProviderException, GenericCryptoException, InvalidKeySpecException, EciesException {
        final byte[] applicationSecret = applicationSecretValue.getBytes(StandardCharsets.UTF_8);
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(resultStatusObject.getServerPublicKey());
        final byte[] transportMasterKeyBytes = Base64.getDecoder().decode(resultStatusObject.getTransportMasterKey());
        final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        return ECIES_FACTORY.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, sharedInfo, parameters);
    }

    /**
     * Encrypts an object using the provided encryptor
     * <p>The object will be serialized to json and the json bytes will be then encrypted</p>
     *
     * @param encryptor Encyptor instance
     * @param value Object value to be encrypted
     * @param parameters ECIES parameters.
     * @return Cryptogram value of the provided object.
     * @throws EciesException when an error during object encryption occurred
     * @throws IOException when an error during object encryption occurred
     */
    public static EciesPayload encryptObject(EciesEncryptor encryptor, Object value, EciesParameters parameters)
            throws EciesException, IOException {
        ByteArrayOutputStream baosL = new ByteArrayOutputStream();
        RestClientConfiguration.defaultMapper().writeValue(baosL, value);
        return encryptor.encrypt(baosL.toByteArray(), parameters);
    }

    /**
     * Decrypts bytes from a response
     *
     * @param decryptor Decryptor
     * @param encryptedResponse Encrypted response
     * @param requestParameters ECIES parameters used to encrypt the request
     * @return decrypted bytes
     * @throws EciesException when an error during decryption occurred
     */
    public static byte[] decryptBytesFromResponse(EciesDecryptor decryptor, EciesEncryptedResponse encryptedResponse, EciesParameters requestParameters)
            throws EciesException {

        final byte[] ephemeralPublicKey = decryptor.getEnvelopeKey().getEphemeralKeyPublic();
        final byte[] mac = Base64.getDecoder().decode(encryptedResponse.getMac());
        final byte[] encryptedData = Base64.getDecoder().decode(encryptedResponse.getEncryptedData());
        // TODO: we trust server here, to do not provide nonce in protocols 3.1 and older in response.
        final byte[] nonce = encryptedResponse.getNonce() != null ? Base64.getDecoder().decode(encryptedResponse.getNonce()) : requestParameters.getNonce();
        final Long timestamp = encryptedResponse.getTimestamp();
        final EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData);

        final EciesParameters responseParameters = new EciesParameters(nonce, requestParameters.getAssociatedData(), timestamp);
        final EciesPayload payload = new EciesPayload(eciesCryptogramResponse, responseParameters);

        return decryptor.decrypt(payload);
    }

    /**
     * Creates an encrypted request instance
     *
     * @param eciesPayload Ecies payload data to be sent
     * @return Encrypted request instance
     */
    public static EciesEncryptedRequest createEncryptedRequest(EciesPayload eciesPayload) {
        EciesEncryptedRequest request = new EciesEncryptedRequest();
        final byte[] nonce = eciesPayload.getParameters().getNonce();
        final Long timestamp = eciesPayload.getParameters().getTimestamp();
        request.setEncryptedData(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEncryptedData()));
        request.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEphemeralPublicKey()));
        request.setMac(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getMac()));
        request.setNonce(nonce != null ? Base64.getEncoder().encodeToString(nonce) : null);
        request.setTimestamp(timestamp);
        return request;
    }

    /**
     * Process an encrypted response for a step.
     * @param stepContext Step context.
     * @param stepId Step identifier.
     * @param eciesScope Scope of ECIES.
     * @param applicationSecret Application's secret.
     * @param associatedData Associated data for ECIES.
     * @throws Exception Thrown in case response decryption fails.
     */
    public static void processEncryptedResponse(StepContext<?, EciesEncryptedResponse> stepContext, String stepId, String applicationSecret, EciesScope eciesScope, byte[] associatedData) throws Exception {
        ResponseContext<EciesEncryptedResponse> responseContext = stepContext.getResponseContext();
        SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
        EciesEncryptor encryptor = securityContext.getEncryptor();

        final PowerAuthVersion version = stepContext.getModel().getVersion();
        final String nonce = responseContext.getResponseBodyObject().getNonce();
        final byte[] nonceBytes = version.useDifferentIvForResponse() && nonce != null ? Base64.getDecoder().decode(nonce) : securityContext.getRequestParameters().getNonce();
        final Long timestamp = responseContext.getResponseBodyObject().getTimestamp();
        final byte[] ephemeralPublicKeyBytes = encryptor.getEnvelopeKey().getEphemeralKeyPublic();
        final byte[] transportMasterKeyBytes = eciesScope == EciesScope.ACTIVATION_SCOPE ? Base64.getDecoder().decode(stepContext.getModel().getResultStatus().getTransportMasterKey()) : null;

        EciesParameters eciesParameters = EciesParameters.builder().nonce(nonceBytes).timestamp(timestamp).associatedData(associatedData).build();

        EciesDecryptor eciesDecryptor;
        if (eciesScope == EciesScope.ACTIVATION_SCOPE) {
            eciesDecryptor = ECIES_FACTORY.getEciesDecryptor(EciesScope.ACTIVATION_SCOPE,
                    encryptor.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes,
                    eciesParameters, ephemeralPublicKeyBytes);
        } else {
            eciesDecryptor = ECIES_FACTORY.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                    encryptor.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), null,
                    eciesParameters, ephemeralPublicKeyBytes);
        }

        final byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(eciesDecryptor, responseContext.getResponseBodyObject(), eciesParameters);

        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        stepContext.getModel().getResultStatus().setResponseData(decryptedMessage);

        stepContext.getStepLogger().writeItem(
                stepId + "-response-decrypt",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                decryptedMessage
        );
    }
}
