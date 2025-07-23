/*
 * PowerAuth Command-line utility
 * Copyright 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.lib.cmd.steps.model;


import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.security.PublicKey;
import java.util.Map;

/**
 * Model representing parameters of the step for sending encrypted data to intermediate server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class EncryptStepModel extends BaseStepModel
        implements EncryptionHeaderData, DryRunCapable {

    /**
     * Request data.
     */
    private byte[] data;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Application secret.
     */
    private String applicationSecret;

    /**
     * Flag indicating that this step should be terminated before the networking call.
     */
    private boolean dryRun;

    /**
     * Master Server Public Key for P-256, a value specific for given application.
     */
    private PublicKey masterPublicKeyP256;

    /**
     * Master Server Public Key for P-384, a value specific for given application.
     */
    private PublicKey masterPublicKeyP384;

    /**
     * Master Server Public Key for ML-DSA-65, a value specific for given application.
     */
    private PublicKey masterPublicKeyMlDsa65;

    /**
     * Algorithm used for the shared secret derivation.
     */
    private SharedSecretAlgorithm sharedSecretAlgorithm;

    /**
     * ECIES encryption scope.
     */
    private String scope;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("DATA", data);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("DRY_RUN", dryRun);
        context.put("MASTER_PUBLIC_KEY_P256", masterPublicKeyP256);
        context.put("MASTER_PUBLIC_KEY_P384", masterPublicKeyP384);
        context.put("MASTER_PUBLIC_KEY_MLDSA65", masterPublicKeyMlDsa65);
        context.put("SCOPE", scope);
        context.put("SHARED_SECRET_ALGORITHM", sharedSecretAlgorithm);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setData((byte[]) context.get("DATA"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setDryRun((boolean) context.get("DRY_RUN"));
        setMasterPublicKeyP256((PublicKey) context.get("MASTER_PUBLIC_KEY_P256"));
        setMasterPublicKeyP384((PublicKey) context.get("MASTER_PUBLIC_KEY_P384"));
        setMasterPublicKeyMlDsa65((PublicKey) context.get("MASTER_PUBLIC_KEY_MLDSA65"));
        setScope((String) context.get("SCOPE"));
        setSharedSecretAlgorithm((SharedSecretAlgorithm) context.get("SHARED_SECRET_ALGORITHM"));
    }

}
