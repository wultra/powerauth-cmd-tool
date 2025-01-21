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

import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
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
        implements DryRunCapable, TokenHeaderData {

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

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> context = super.toMap();
        context.put("TOKEN_ID", tokenId);
        context.put("TOKEN_SECRET", tokenSecret);
        context.put("HTTP_METHOD", httpMethod);
        context.put("DATA", data);
        context.put("DRY_RUN", dryRun);
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
    }

}
