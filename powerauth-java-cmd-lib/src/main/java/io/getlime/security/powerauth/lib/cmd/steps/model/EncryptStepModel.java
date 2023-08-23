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
package io.getlime.security.powerauth.lib.cmd.steps.model;


import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ReplayAttackCapable;
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
        implements EncryptionHeaderData, DryRunCapable, ReplayAttackCapable {

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
     * Master Server Public Key, a value specific for given application.
     */
    private PublicKey masterPublicKey;

    /**
     * ECIES encryption scope.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     */
    private String scope;

    /**
     * Flag indicating that this step should retry its networking call to simulate replay attack.
     */
    private boolean isReplayAttack;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("DATA", data);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("DRY_RUN", dryRun);
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("SCOPE", scope);
        context.put("REPLAY_ATTACK", isReplayAttack);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setData((byte[]) context.get("DATA"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setDryRun((boolean) context.get("DRY_RUN"));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setScope((String) context.get("SCOPE"));
        setReplayAttack((boolean) context.getOrDefault("REPLAY_ATTACK", false));
    }

}
