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

import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import lombok.Builder;
import lombok.Data;

import javax.crypto.SecretKey;

/**
 * Temporary key context used for deriving temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@Builder
public class TemporaryKeyContext {

    /**
     * Temporary key identifier
     */
    private String temporaryKeyId;

    /**
     * Temporary public key (V3)
     */
    private String temporaryPublicKey;

    /**
     * Shared secret client context for shared secret derivation (V4)
     */
    private SharedSecretClientContext sharedSecretClientContext;

    /**
     * Temporary shared secret (V4)
     */
    private SecretKey temporarySharedSecret;

}
