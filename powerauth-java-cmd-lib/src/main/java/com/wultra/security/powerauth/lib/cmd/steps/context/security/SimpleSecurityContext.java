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
package com.wultra.security.powerauth.lib.cmd.steps.context.security;

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import lombok.Builder;
import lombok.Data;

/**
 * Simple security context
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data
@Builder
public class SimpleSecurityContext implements SecurityContext {
    /**
     * Encryptor
     */
    private ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> encryptor;

    @Override
    public EncryptorScope getEncryptorScope() {
        return encryptor != null ? encryptor.getEncryptorId().scope() : null;
    }
}
