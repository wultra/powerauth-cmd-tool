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
package com.wultra.security.powerauth.lib.cmd.util;

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Helper class with security utilities.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class SecurityUtil {

    /**
     * Encrypts an object using the provided encryptor
     * <p>The object will be serialized to json and the json bytes will be then encrypted</p>
     *
     * @param encryptor Encyptor instance
     * @param value Object value to be encrypted
     * @return Cryptogram value of the provided object.
     * @throws EncryptorException when an error during object encryption occurred
     * @throws IOException when an error during object encryption occurred
     */
    public static EncryptedRequest encryptObject(ClientEncryptor<?, ?> encryptor, Object value)
            throws EncryptorException, IOException {
        ByteArrayOutputStream baosL = new ByteArrayOutputStream();
        RestClientConfiguration.defaultMapper().writeValue(baosL, value);
        return encryptor.encryptRequest(baosL.toByteArray());
    }

    /**
     * Process an encrypted response for a step.
     * @param stepContext Step context.
     * @param stepId Step identifier.
     * @throws Exception Thrown in case response decryption fails.
     */
    public static void processEncryptedResponse(StepContext<?, EncryptedResponse> stepContext, String stepId) throws Exception {
        final SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
        final byte[] decryptedBytes = decryptResponseData(stepContext, securityContext);

        final String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        stepContext.getModel().getResultStatus().setResponseData(decryptedMessage);

        stepContext.getStepLogger().writeItem(
                stepId + "-response-decrypt",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                decryptedMessage
        );
    }

    /**
     * Decrypt response data.
     * @param stepContext Step context.
     * @param securityContext Security context.
     * @return Decrypted data.
     * @throws EncryptorException In case decryption fails.
     */
    public static byte[] decryptResponseData(StepContext<?, EncryptedResponse> stepContext, SimpleSecurityContext securityContext) throws EncryptorException {
        return switch (stepContext.getModel().getVersion().getMajorVersion()) {
            case 3 -> {
                final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepContext.getResponseContext().getResponseBodyObject();
                yield securityContext.getEncryptor().decryptResponse(new EciesEncryptedResponse(
                        eciesResponse.getEncryptedData(),
                        eciesResponse.getMac(),
                        eciesResponse.getNonce(),
                        eciesResponse.getTimestamp()
                ));
            }
            case 4 -> {
                final AeadEncryptedResponse aeadResponse = (AeadEncryptedResponse) stepContext.getResponseContext().getResponseBodyObject();
                yield securityContext.getEncryptor().decryptResponse(new AeadEncryptedResponse(
                        aeadResponse.getEncryptedData(),
                        aeadResponse.getTimestamp()
                ));
            }
            default ->
                    throw new IllegalStateException("Unsupported version: " + stepContext.getModel().getVersion());
        };
    }

    /**
     * Resolve which shared secret algorithm will be used, either configured or default one.
     * @param stepContext Step context.
     * @param scope Encryptor scope.
     * @return Shared secret algorithm.
     */
    public static SharedSecretAlgorithm resolveSharedSecretAlgorithm(StepContext<?, ?> stepContext, EncryptorScope scope) {
        return switch (scope) {
            case APPLICATION_SCOPE -> {
                SharedSecretAlgorithm sharedSecretAlgorithm = (SharedSecretAlgorithm) stepContext.getModel().toMap().get("SHARED_SECRET_ALGORITHM");
                if (sharedSecretAlgorithm == null) {
                    // No shared secret algorithm is configured for the step, used the default one
                    sharedSecretAlgorithm = SecurityUtil.getDefaultSharedSecretAlgorithm(stepContext.getModel().getVersion());
                }
                yield sharedSecretAlgorithm;
            }
            case ACTIVATION_SCOPE -> SharedSecretAlgorithm.valueOf(stepContext.getModel().getResultStatus().getSharedSecretAlgorithm());
        };
    }

    /**
     * Get default shared secret algorithm.
     * @param version Cryptography protocol version.
     * @return Default shared secret algorithm.
     */
    public static SharedSecretAlgorithm getDefaultSharedSecretAlgorithm(PowerAuthVersion version) {
        return switch (version.getMajorVersion()) {
            case 3:
                yield SharedSecretAlgorithm.EC_P256;
            case 4:
                // Prefer hybrid algorithm for crypto4
                yield SharedSecretAlgorithm.EC_P384_ML_L3;
            default:
                throw new IllegalArgumentException("Unsupported version: " + version);
        };
    }
}
