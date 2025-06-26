/*
 * PowerAuth Command-line utility
 * Copyright 2025 Wultra s.r.o.
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

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;

import javax.crypto.SecretKey;

/**
 * Utility class for deriving factor keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class FactorKeyUtil {

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    /**
     * Derive a factor key.
     * @param response Shared secret response.
     * @param clientContext Client context.
     * @param algorithm Shared secret algorithm.
     * @return Factor key.
     * @throws GenericCryptoException In case any cryptography error occurs.
     */
    public static SecretKey deriveFactorKey(SharedSecretResponse response, SharedSecretClientContext clientContext, SharedSecretAlgorithm algorithm) throws GenericCryptoException {
        return switch (algorithm) {
            case EC_P384 -> {
                final SharedSecretClientContextEcdhe clientContextEcdhe = (SharedSecretClientContextEcdhe) clientContext;
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
                sharedSecretResponseEcdhe.setEcServerPublicKey(response.getEcdhe());
                yield SHARED_SECRET_ECDHE.computeSharedSecret(clientContextEcdhe, sharedSecretResponseEcdhe);
            }
            case EC_P384_ML_L3 -> {
                final SharedSecretClientContextHybrid clientContextHybrid = (SharedSecretClientContextHybrid) clientContext;
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
                sharedSecretResponseHybrid.setEcServerPublicKey(response.getEcdhe());
                sharedSecretResponseHybrid.setPqcCiphertext(response.getMlkem());
                yield SHARED_SECRET_HYBRID.computeSharedSecret(clientContextHybrid, sharedSecretResponseHybrid);
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
    }

}
