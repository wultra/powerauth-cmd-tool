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
package com.wultra.security.powerauth.lib.cmd.header;

import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenAndEncryptionHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;

import static com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY;

/**
 * Token and encryption header provider.
 *
 * @author Roman Strobl, roman.strob@wultra.com
 */
public class TokenAndEncryptionHeaderProvider implements PowerAuthHeaderProvider<TokenAndEncryptionHeaderData> {

    /**
     * Adds a token and encryption headers to the request context
     * @param stepContext Step context
     */
    @Override
    public void addHeader(StepContext<? extends TokenAndEncryptionHeaderData, ?> stepContext) throws Exception {
        TokenHeaderData tokenHeaderData = stepContext.getModel();
        POWER_AUTH_HEADER_FACTORY.getHeaderProvider(tokenHeaderData).addHeader(stepContext);
        EncryptionHeaderData encryptionHeaderData = stepContext.getModel();
        POWER_AUTH_HEADER_FACTORY.getHeaderProvider(encryptionHeaderData).addHeader(stepContext);
    }

}