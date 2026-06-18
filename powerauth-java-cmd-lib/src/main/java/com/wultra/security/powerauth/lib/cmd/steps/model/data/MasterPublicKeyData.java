/*
 * PowerAuth Command-line utility
 * Copyright 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.lib.cmd.steps.model.data;

import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;

import java.security.PublicKey;

/**
 * Data providing master public keys used for key derivation.
 * Extends {@link SharedSecretData} so both the algorithm and the keys
 * are available via a single interface check.
 * <p>
 * The P-256 key is optional: models that do not support the P-256 curve
 * (e.g. the upgrade step) return {@code null} from the default implementation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface MasterPublicKeyData {

    /**
     * @return Shared secret algorithm.
     */
    SharedSecretAlgorithm getSharedSecretAlgorithm();

    /**
     * @return Master public key for P-256, or {@code null} if the P-256 curve is not supported.
     */
    default PublicKey getMasterPublicKeyP256() {
        return null;
    }

    /**
     * @return Master public key for P-384.
     */
    PublicKey getMasterPublicKeyP384();

    /**
     * @return Master public key for ML-DSA-65.
     */
    PublicKey getMasterPublicKeyMlDsa65();

    /**
     * @return Master public key for ML-DSA-87.
     */
    PublicKey getMasterPublicKeyMlDsa87();

}

