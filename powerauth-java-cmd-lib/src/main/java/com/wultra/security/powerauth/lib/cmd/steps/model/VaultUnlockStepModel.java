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

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.AuthenticationHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

/**
 * Model representing parameters of the step for unlocking secure vault.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class VaultUnlockStepModel extends BaseStepModel
        implements ResultStatusChangeable, AuthenticationHeaderData {

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Application secret.
     */
    private String applicationSecret;

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * PowerAuth authentication code type
     */
    private PowerAuthCodeType authenticationCodeType;

    /**
     * Password for the password related key encryption.
     */
    private String password;

    /**
     * Reason why vault is being unlocked.
     */
    private String reason;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("AUTHENTICATION_CODE_TYPE", authenticationCodeType.toString());
        context.put("PASSWORD", password);
        context.put("REASON", reason);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setAuthenticationCodeType(PowerAuthCodeType.getEnumFromString((String) context.get("AUTHENTICATION_CODE_TYPE")));
        setPassword((String) context.get("PASSWORD"));
        setReason((String) context.get("REASON"));
    }

}
