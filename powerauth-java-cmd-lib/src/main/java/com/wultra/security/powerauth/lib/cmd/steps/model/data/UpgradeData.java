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
package com.wultra.security.powerauth.lib.cmd.steps.model.data;

import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;

import java.security.PublicKey;

/**
 * Data used in upgrade step
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface UpgradeData extends ResultStatusChangeable, BaseStepData {

    /**
     * @return Application key.
     */
    String getApplicationKey();

    /**
     * @return Application secret.
     */
    String getApplicationSecret();

    /**
     * @return Base64 encoded master public key for P-384.
     */
    PublicKey getMasterPublicKeyP384();

    /**
     * @return Base64 encoded master public key for P-384.
     */
    PublicKey getMasterPublicKeyMlDsa65();

    /**
     * @return Shared secret algorithm.
     */
    SharedSecretAlgorithm getSharedSecretAlgorithm();

}
