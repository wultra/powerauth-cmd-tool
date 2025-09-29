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
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecret;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecretEcdhe;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecretHybrid;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;

import javax.crypto.SecretKey;
import java.util.function.Consumer;

/**
 * Shared secret derivation utility class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SharedSecretUtil {

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    /**
     * Build shared secret request.
     * @param algorithm Shared secret algorithm.
     * @param clientContextConsumer Consumer for the client context.
     * @return Shared secret request.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public static RequestSharedSecret buildSharedSecretRequest(SharedSecretAlgorithm algorithm, Consumer<SharedSecretClientContext> clientContextConsumer) throws GenericCryptoException {
        return switch (algorithm) {
            case EC_P384 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
                clientContextConsumer.accept(requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestEcdhe requestEcdhe = (SharedSecretRequestEcdhe) requestCryptogram.getSharedSecretRequest();
                final RequestSharedSecretEcdhe sharedSecretRequest = new RequestSharedSecretEcdhe();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestEcdhe.getEcClientPublicKey());
                yield sharedSecretRequest;
            }
            case EC_P384_ML_L3 -> {
                final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
                clientContextConsumer.accept(requestCryptogram.getSharedSecretClientContext());
                final SharedSecretRequestHybrid requestHybrid = (SharedSecretRequestHybrid) requestCryptogram.getSharedSecretRequest();
                final RequestSharedSecretHybrid sharedSecretRequest = new RequestSharedSecretHybrid();
                sharedSecretRequest.setAlgorithm(algorithm.toString());
                sharedSecretRequest.setEcdhe(requestHybrid.getEcClientPublicKey());
                sharedSecretRequest.setMlkem(requestHybrid.getPqcEncapsulationKey());
                yield sharedSecretRequest;
            }
            default -> throw new IllegalStateException("Unsupported algorithm for version 4: " + algorithm);
        };
    }

    /**
     * Derive shared secret.
     * @param sharedSecretResponse Shared secret response.
     * @param clientContext Client context from shared secret request.
     * @param sharedSecretAlgorithm Shared secret algorithm.
     * @return Derived shared secret.
     * @throws GenericCryptoException Thrown in case shared secret derivation fails.
     */
    public static SecretKey deriveSharedSecret(SharedSecretResponse sharedSecretResponse, SharedSecretClientContext clientContext, SharedSecretAlgorithm sharedSecretAlgorithm) throws GenericCryptoException {
        switch (sharedSecretAlgorithm) {
            case EC_P384 -> {
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
                sharedSecretResponseEcdhe.setEcServerPublicKey(sharedSecretResponse.getEcdhe());
                return SHARED_SECRET_ECDHE.computeSharedSecret((SharedSecretClientContextEcdhe) clientContext, sharedSecretResponseEcdhe);
            }
            case EC_P384_ML_L3 -> {
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
                sharedSecretResponseHybrid.setEcServerPublicKey(sharedSecretResponse.getEcdhe());
                sharedSecretResponseHybrid.setPqcCiphertext(sharedSecretResponse.getMlkem());
                return SHARED_SECRET_HYBRID.computeSharedSecret((SharedSecretClientContextHybrid) clientContext, sharedSecretResponseHybrid);
            }
            default -> throw new IllegalStateException("Unsupported shared secret algorithm: " + sharedSecretAlgorithm);
        }
    }

}
