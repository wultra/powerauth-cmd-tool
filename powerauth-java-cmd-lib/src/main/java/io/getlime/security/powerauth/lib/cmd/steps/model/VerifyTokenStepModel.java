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

import io.getlime.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ReplayAttackCapable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

/**
 * Model representing parameters of the step for verifying token digest.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class VerifyTokenStepModel extends BaseStepModel
        implements DryRunCapable, TokenHeaderData, ReplayAttackCapable {

    /**
     * Token ID.
     */
    private String tokenId;

    /**
     * Token secret.
     */
    private String tokenSecret;

    /**
     * HTTP method.
     */
    private String httpMethod;

    /**
     * HTTP request data.
     */
    private byte[] data;

    /**
     * Flag indicating that this step should be terminated before the networking call.
     */
    private boolean dryRun;

    /**
     * Flag indicating that this step should retry its networking call to simulate replay attack.
     */
    private boolean isReplayAttack;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("TOKEN_ID", tokenId);
        context.put("TOKEN_SECRET", tokenSecret);
        context.put("HTTP_METHOD", httpMethod);
        context.put("DATA", data);
        context.put("DRY_RUN", dryRun);
        context.put("REPLAY_ATTACK", isReplayAttack);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setTokenId((String) context.get("TOKEN_ID"));
        setTokenSecret((String) context.get("TOKEN_SECRET"));
        setHttpMethod((String) context.get("HTTP_METHOD"));
        setData((byte[]) context.get("DATA"));
        setDryRun((boolean) context.get("DRY_RUN"));
        setReplayAttack((boolean) context.getOrDefault("REPLAY_ATTACK", false));
    }

}
