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

import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;

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
    public static EncryptedRequest encryptObject(ClientEncryptor encryptor, Object value)
            throws EncryptorException, IOException {
        ByteArrayOutputStream baosL = new ByteArrayOutputStream();
        RestClientConfiguration.defaultMapper().writeValue(baosL, value);
        return encryptor.encryptRequest(baosL.toByteArray());
    }


    /**
     * Creates an encrypted request instance
     *
     * @param encryptedRequest Ecies payload data to be sent
     * @return Encrypted request instance
     */
    public static EciesEncryptedRequest createEncryptedRequest(EncryptedRequest encryptedRequest) {
        EciesEncryptedRequest request = new EciesEncryptedRequest();
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setMac(encryptedRequest.getMac());
        request.setNonce(encryptedRequest.getNonce());
        request.setTimestamp(encryptedRequest.getTimestamp());
        return request;
    }

    /**
     * Process an encrypted response for a step.
     * @param stepContext Step context.
     * @param stepId Step identifier.
     * @throws Exception Thrown in case response decryption fails.
     */
    public static void processEncryptedResponse(StepContext<?, EciesEncryptedResponse> stepContext, String stepId) throws Exception {
        ResponseContext<EciesEncryptedResponse> responseContext = stepContext.getResponseContext();
        SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();

        EciesEncryptedResponse responseObject = responseContext.getResponseBodyObject();
        final byte[] decryptedBytes = securityContext.getEncryptor().decryptResponse(new EncryptedResponse(
                responseObject.getEncryptedData(),
                responseObject.getMac(),
                responseObject.getNonce(),
                responseObject.getTimestamp()
        ));

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
