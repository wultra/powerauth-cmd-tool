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
 * Model representing step for creating a new token.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class CreateTokenStepModel extends BaseStepModel
        implements AuthenticationHeaderData, ResultStatusChangeable {

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
     * PowerAuth authentication code type.
     */
    private PowerAuthCodeType authenticationCodeType;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("APPLICATION_KEY", applicationKey);
        context.put("APPLICATION_SECRET", applicationSecret);
        context.put("PASSWORD", password);
        context.put("AUTHENTICATION_CODE_TYPE", authenticationCodeType.toString());
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setApplicationKey((String) context.get("APPLICATION_KEY"));
        setApplicationSecret((String) context.get("APPLICATION_SECRET"));
        setPassword((String) context.get("PASSWORD"));
        setAuthenticationCodeType(PowerAuthCodeType.getEnumFromString((String) context.get("AUTHENTICATION_CODE_TYPE")));
    }

}
