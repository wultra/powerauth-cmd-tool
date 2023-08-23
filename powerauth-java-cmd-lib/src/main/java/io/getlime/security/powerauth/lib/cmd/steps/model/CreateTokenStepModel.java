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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ReplayAttackCapable;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.security.PublicKey;
import java.util.Map;

/**
 * Model representing step for creating a new token.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class CreateTokenStepModel extends BaseStepModel
        implements SignatureHeaderData, ResultStatusChangeable, ReplayAttackCapable {

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Application secret.
     */
    private String applicationSecret;

    /**
     * Password for the password related key encryption.
     */
    private String password;

    /**
     * PowerAuth signature type.
     */
    private PowerAuthSignatureTypes signatureType;

    /**
     * Master Server Public Key, a value specific for given application.
     */
    private PublicKey masterPublicKey;

    /**
     * Flag indicating that this step should retry its networking call to simulate replay attack.
     */
    private boolean isReplayAttack;


    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        context.put("SIGNATURE_TYPE", signatureType.toString());
        context.put("MASTER_PUBLIC_KEY", masterPublicKey);
        context.put("REPLAY_ATTACK", isReplayAttack);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setPassword((String) context.get("PASSWORD"));
        setSignatureType(PowerAuthSignatureTypes.getEnumFromString((String) context.get("SIGNATURE_TYPE")));
        setMasterPublicKey((PublicKey) context.get("MASTER_PUBLIC_KEY"));
        setReplayAttack((boolean) context.getOrDefault("REPLAY_ATTACK", false));
    }

}
