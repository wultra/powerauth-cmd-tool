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

import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeLegacyUtils;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.AuthenticationHeaderData;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.HttpUtil;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Authentication header provider
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class AuthenticationHeaderProvider implements PowerAuthHeaderProvider<AuthenticationHeaderData> {

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private static final AuthenticationCodeUtils AUTHENTICATION_CODE_UTILS = new AuthenticationCodeUtils();
    private static final AuthenticationCodeLegacyUtils AUTHENTICATION_CODE_LEGACY_UTILS = new AuthenticationCodeLegacyUtils();

    /**
     * Adds an authentication header to the request context
     * @param stepContext Step context
     * @throws Exception when an error during adding of an authentication header occurred
     */
    @Override
    public void addHeader(StepContext<? extends AuthenticationHeaderData, ?> stepContext) throws Exception {
        AuthenticationHeaderData model = stepContext.getModel();
        RequestContext requestContext = stepContext.getRequestContext();
        ResultStatusObject resultStatusObject = model.getResultStatus();

        // Get the factor keys
        SecretKey possessionFactorKey = resultStatusObject.getPossessionFactorKeyObject();
        SecretKey biometryFactorKey = resultStatusObject.getBiometryFactorKeyObject();

        // Generate nonce
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);

        byte[] requestBytes = HttpUtil.toRequestBytes(requestContext.getRequestObject());

        // Compute the current PowerAuth authentication code for possession and knowledge factor
        String authBaseString = PowerAuthHttpBody.getAuthenticationBaseString(requestContext.getAuthenticationHttpMethod(), requestContext.getAuthenticationRequestUri(), nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(resultStatusObject, stepContext.getStepLogger());
        final PowerAuthAuthenticationCodeFormat format = PowerAuthAuthenticationCodeFormat.getFormatForVersion(model.getVersion().value());
        final AuthenticationCodeConfiguration config = AuthenticationCodeConfiguration.forFormat(format);

        List<SecretKey> authSecretKeys;
        if (PowerAuthCodeType.POSSESSION.equals(model.getAuthenticationCodeType())) {
            authSecretKeys = Collections.singletonList(possessionFactorKey);
        } else if (PowerAuthCodeType.POSSESSION_KNOWLEDGE.equals(model.getAuthenticationCodeType())) {
            SecretKey knowledgeFactorKey = getKnowledgeKeyFactor(model);
            authSecretKeys = Arrays.asList(possessionFactorKey, knowledgeFactorKey);
        } else {
            SecretKey knowledgeFactorKey = getKnowledgeKeyFactor(model);
            authSecretKeys = KEY_FACTORY.keysForAuthenticationCodeType(model.getAuthenticationCodeType(), possessionFactorKey, knowledgeFactorKey, biometryFactorKey);
        }

        String authCodeValue = switch (model.getVersion().getMajorVersion()) {
            case 3 -> AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode(authBaseString.getBytes(StandardCharsets.UTF_8), authSecretKeys, ctrData, config);
            case 4 -> AUTHENTICATION_CODE_UTILS.computeAuthCode(authBaseString.getBytes(StandardCharsets.UTF_8), authSecretKeys, ctrData, config);
            default -> throw new IllegalStateException("Unsupported version: " + stepContext.getModel().getVersion());
        };

        PowerAuthAuthorizationHttpHeader header = new PowerAuthAuthorizationHttpHeader(resultStatusObject.getActivationId(), model.getApplicationKey(), authCodeValue, model.getAuthenticationCodeType().toString(), Base64.getEncoder().encodeToString(nonceBytes), model.getVersion().value());

        Map<String, String> lowLevelData = new HashMap<>();
        lowLevelData.put("counter", String.valueOf(resultStatusObject.getCounter()));
        int version = resultStatusObject.getVersion().intValue();
        if (version == 3) {
            lowLevelData.put("ctrData", Base64.getEncoder().encodeToString(ctrData));
        }
        lowLevelData.put("authenticationBaseString", authBaseString);
        lowLevelData.put("nonce", Base64.getEncoder().encodeToString(nonceBytes));
        lowLevelData.put("applicationSecret", model.getApplicationSecret());

        if (model instanceof VerifyAuthenticationStepModel) {
            lowLevelData.put("activationId", resultStatusObject.getActivationId());
            lowLevelData.put("applicationKey", model.getApplicationKey());
            lowLevelData.put("resourceId", ((VerifyAuthenticationStepModel) model).getResourceId());
            lowLevelData.put("serverPublicKey", resultStatusObject.getEcServerPublicKey());
            lowLevelData.put("transportKey", resultStatusObject.getTransportMasterKey());
        }

        stepContext.getStepLogger().writeItem(
                stepContext.getStep().id() + "-prepare-request",
                "Authentication Code Calculation Parameters",
                "Low level cryptographic inputs required to compute authentication code - mainly an authentication base string and a counter value.",
                "OK",
                lowLevelData
        );

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.setAuthorizationHeaderName(PowerAuthAuthorizationHttpHeader.HEADER_NAME);
        requestContext.getHttpHeaders().put(PowerAuthAuthorizationHttpHeader.HEADER_NAME, headerValue);
    }

    private <M extends AuthenticationHeaderData> SecretKey getKnowledgeKeyFactor(M model) throws Exception {
        byte[] knowledgeKeyFactorSalt = model.getResultStatus().getKnowledgeFactorKeySaltBytes();
        byte[] knowledgeKeyFactorEncryptedBytes = model.getResultStatus().getKnowledgeFactorKeyEncryptedBytes();

        // Ask for the password to unlock knowledge factor key
        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        return EncryptedStorageUtil.getKnowledgeFactorKey(password, knowledgeKeyFactorEncryptedBytes, knowledgeKeyFactorSalt, KEY_GENERATOR);
    }

}
