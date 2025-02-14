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
package com.wultra.security.powerauth.lib.cmd.header;

import com.wultra.security.powerauth.crypto.client.token.ClientTokenGenerator;
import com.wultra.security.powerauth.http.PowerAuthTokenHttpHeader;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Token header provider
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class TokenHeaderProvider implements PowerAuthHeaderProvider<TokenHeaderData> {

    /**
     * Adds a token header to the request context
     * @param stepContext Step context
     */
    @Override
    public void addHeader(StepContext<? extends TokenHeaderData, ?> stepContext) throws Exception {
        TokenHeaderData model = stepContext.getModel();
        RequestContext requestContext = stepContext.getRequestContext();

        String tokenId = model.getTokenId();
        byte[] tokenSecret = Base64.getDecoder().decode(model.getTokenSecret());

        final ClientTokenGenerator tokenGenerator = new ClientTokenGenerator();
        final String version = model.getVersion().value();
        final byte[] tokenNonce = tokenGenerator.generateTokenNonce();
        final byte[] tokenTimestamp = tokenGenerator.generateTokenTimestamp();
        final byte[] tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, version, tokenSecret);

        PowerAuthTokenHttpHeader header = new PowerAuthTokenHttpHeader(
                tokenId,
                Base64.getEncoder().encodeToString(tokenDigest),
                Base64.getEncoder().encodeToString(tokenNonce),
                new String(tokenTimestamp, StandardCharsets.UTF_8),
                version
        );

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.setAuthorizationHeaderName(PowerAuthTokenHttpHeader.HEADER_NAME);
        requestContext.getHttpHeaders().put(PowerAuthTokenHttpHeader.HEADER_NAME, headerValue);
    }

}
