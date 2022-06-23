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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import java.nio.charset.StandardCharsets;

/**
 * Utility class for ECIES encryption processing.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EncryptionUtil {

    /**
     * Process an encrypted response for a step.
     * @param stepContext Step context.
     * @param stepId Step identifier.
     * @throws Exception Thrown in case response decryption fails.
     */
    public static void processEncryptedResponse(StepContext<?, EciesEncryptedResponse> stepContext, String stepId) throws Exception {
        ResponseContext<EciesEncryptedResponse> responseContext = stepContext.getResponseContext();
        EciesEncryptor encryptor = ((SimpleSecurityContext) stepContext.getSecurityContext()).getEncryptor();
        final byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(encryptor, responseContext.getResponseBodyObject());

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