/*
 * PowerAuth Command-line utility
 * Copyright 2022 Wultra s.r.o.
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

import com.wultra.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

/**
 * Model representing parameters of the step for computing offline signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class ComputeOfflineSignatureStepModel extends BaseStepModel implements ResultStatusChangeable, DryRunCapable {

    /**
     * File name of the file with stored activation status.
     */
    private String statusFileName;

    /**
     * QR code data.
     */
    private String qrCodeData;

    /**
     * Knowledge key password (PIN).
     */
    private String password;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("STATUS_FILENAME", statusFileName);
        context.put("QR_CODE_DATA", qrCodeData);
        context.put("PASSWORD", password);
        return context;
    }

    @Override
    public void fromMap(Map<String, Object> context) {
        super.fromMap(context);
        setStatusFileName((String) context.get("STATUS_FILENAME"));
        setQrCodeData((String) context.get("QR_CODE_DATA"));
        setPassword((String) context.get("PASSWORD"));
    }

    @Override
    public boolean isDryRun() {
        return true;
    }

}
