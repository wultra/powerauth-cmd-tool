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
package io.getlime.security.powerauth.lib.cmd.header;

import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SecurityContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;

/**
 * Encryption header provider
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class EncryptionHeaderProvider implements PowerAuthHeaderProvider<EncryptionHeaderData> {

    /**
     * Adds an encryption header to the request context
     * @param stepContext Step context
     */
    @Override
    public void addHeader(StepContext<? extends EncryptionHeaderData, ?> stepContext) {
        EncryptionHeaderData model = stepContext.getModel();
        EncryptorScope encryptorScope = stepContext.getSecurityContext().getEncryptorScope();
        if (encryptorScope == null) {
            // Scope is not determined yet. To fix this, move call to "addHeader()" after "addEncryptedRequest" call.
            throw new IllegalStateException("Scope of encryption is not yet determined");
        }
        String activationId = encryptorScope == EncryptorScope.ACTIVATION_SCOPE ? model.getResultStatus().getActivationId() : null;
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
        String headerValue = header.buildHttpHeader();

        RequestContext requestContext = stepContext.getRequestContext();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.setAuthorizationHeaderName(PowerAuthEncryptionHttpHeader.HEADER_NAME);
        requestContext.getHttpHeaders().put(PowerAuthEncryptionHttpHeader.HEADER_NAME, headerValue);
    }

}
