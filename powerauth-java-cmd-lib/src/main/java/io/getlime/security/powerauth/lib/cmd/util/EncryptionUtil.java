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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for ECIES encryption processing.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EncryptionUtil {

    private static final EciesFactory ECIES_FACTORY = new EciesFactory();

    /**
     * Process an encrypted response for a step.
     * @param stepContext Step context.
     * @param stepId Step identifier.
     * @throws Exception Thrown in case response decryption fails.
     */
    public static void processEncryptedResponse(StepContext<?, EciesEncryptedResponse> stepContext, String stepId, String applicationSecret, EciesScope eciesScope, byte[] associatedData) throws Exception {
        ResponseContext<EciesEncryptedResponse> responseContext = stepContext.getResponseContext();
        EciesEncryptor encryptor = ((SimpleSecurityContext) stepContext.getSecurityContext()).getEncryptor();

        final String nonce = responseContext.getResponseBodyObject().getNonce();
        final byte[] nonceBytes = nonce != null ? Base64.getDecoder().decode(nonce) : null;
        final Long timestamp = responseContext.getResponseBodyObject().getTimestamp();
        final String ephemeralPublicKey = responseContext.getResponseBodyObject().getEphemeralPublicKey();
        final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(ephemeralPublicKey);
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

        final byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(eciesDecryptor, responseContext.getResponseBodyObject(), associatedData);

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