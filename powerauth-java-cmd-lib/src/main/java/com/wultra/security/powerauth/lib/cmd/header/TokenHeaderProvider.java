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

import com.wultra.security.powerauth.http.PowerAuthTokenHttpHeader;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
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

        final String version = model.getVersion().value();
        final PowerAuthVersion powerAuthVersion = PowerAuthVersion.fromValue(version);
        final byte[] tokenNonce;
        final byte[] tokenTimestamp;
        final byte[] tokenDigest;
        switch (powerAuthVersion.getMajorVersion()) {
            case 3 -> {
                final com.wultra.security.powerauth.crypto.client.token.ClientTokenGenerator tokenGenerator = new com.wultra.security.powerauth.crypto.client.token.ClientTokenGenerator();
                tokenNonce = tokenGenerator.generateTokenNonce();
                tokenTimestamp = tokenGenerator.generateTokenTimestamp();
                tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, version, tokenSecret);
            }
            case 4 -> {
                final com.wultra.security.powerauth.crypto.client.v4.token.ClientTokenGenerator tokenGenerator = new com.wultra.security.powerauth.crypto.client.v4.token.ClientTokenGenerator();
                tokenNonce = tokenGenerator.generateTokenNonce();
                tokenTimestamp = tokenGenerator.generateTokenTimestamp();
                tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, version, tokenSecret);
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        }

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
