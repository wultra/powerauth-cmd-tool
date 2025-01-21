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
import com.wultra.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import com.wultra.security.powerauth.crypto.lib.config.SignatureConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
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
 * Signature header provider
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class SignatureHeaderProvider implements PowerAuthHeaderProvider<SignatureHeaderData> {

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private static final PowerAuthClientSignature SIGNATURE = new PowerAuthClientSignature();

    /**
     * Adds a signature header to the request context
     * @param stepContext Step context
     * @throws Exception when an error during adding of a signature header occurred
     */
    @Override
    public void addHeader(StepContext<? extends SignatureHeaderData, ?> stepContext) throws Exception {
        SignatureHeaderData model = stepContext.getModel();
        RequestContext requestContext = stepContext.getRequestContext();
        ResultStatusObject resultStatusObject = model.getResultStatus();

        // Get the signature keys
        SecretKey signaturePossessionKey = resultStatusObject.getSignaturePossessionKeyObject();
        SecretKey signatureBiometryKey = resultStatusObject.getSignatureBiometryKeyObject();

        // Generate nonce
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);

        byte[] requestBytes = HttpUtil.toRequestBytes(requestContext.getRequestObject());

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(requestContext.getSignatureHttpMethod(), requestContext.getSignatureRequestUri(), nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(resultStatusObject, stepContext.getStepLogger());
        final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion().value());
        final SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);

        List<SecretKey> signatureSecretKeys;
        if (PowerAuthSignatureTypes.POSSESSION.equals(model.getSignatureType())) {
            signatureSecretKeys = Collections.singletonList(signaturePossessionKey);
        } else if (PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE.equals(model.getSignatureType())) {
            SecretKey signatureKnowledgeKey = getSignatureKnowledgeKey(model);
            signatureSecretKeys = Arrays.asList(signaturePossessionKey, signatureKnowledgeKey);
        } else {
            SecretKey signatureKnowledgeKey = getSignatureKnowledgeKey(model);
            signatureSecretKeys = KEY_FACTORY.keysForSignatureType(model.getSignatureType(), signaturePossessionKey, signatureKnowledgeKey, signatureBiometryKey);
        }
        String signatureValue = SIGNATURE.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), signatureSecretKeys, ctrData, signatureConfiguration);

        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(resultStatusObject.getActivationId(), model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), Base64.getEncoder().encodeToString(nonceBytes), model.getVersion().value());

        Map<String, String> lowLevelData = new HashMap<>();
        lowLevelData.put("counter", String.valueOf(resultStatusObject.getCounter()));
        int version = resultStatusObject.getVersion().intValue();
        if (version == 3) {
            lowLevelData.put("ctrData", Base64.getEncoder().encodeToString(ctrData));
        }
        lowLevelData.put("signatureBaseString", signatureBaseString);
        lowLevelData.put("nonce", Base64.getEncoder().encodeToString(nonceBytes));
        lowLevelData.put("applicationSecret", model.getApplicationSecret());

        if (model instanceof VerifySignatureStepModel) {
            lowLevelData.put("activationId", resultStatusObject.getActivationId());
            lowLevelData.put("applicationKey", model.getApplicationKey());
            lowLevelData.put("resourceId", ((VerifySignatureStepModel) model).getResourceId());
            lowLevelData.put("serverPublicKey", resultStatusObject.getServerPublicKey());
            lowLevelData.put("transportKey", resultStatusObject.getTransportMasterKey());
        }

        stepContext.getStepLogger().writeItem(
                stepContext.getStep().id() + "-prepare-request",
                "Signature Calculation Parameters",
                "Low level cryptographic inputs required to compute signature - mainly a signature base string and a counter value.",
                "OK",
                lowLevelData
        );

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.setAuthorizationHeaderName(PowerAuthSignatureHttpHeader.HEADER_NAME);
        requestContext.getHttpHeaders().put(PowerAuthSignatureHttpHeader.HEADER_NAME, headerValue);
    }

    private <M extends SignatureHeaderData> SecretKey getSignatureKnowledgeKey(M model) throws Exception {
        byte[] signatureKnowledgeKeySalt = model.getResultStatus().getSignatureKnowledgeKeySaltBytes();
        byte[] signatureKnowledgeKeyEncryptedBytes = model.getResultStatus().getSignatureKnowledgeKeyEncryptedBytes();

        // Ask for the password to unlock knowledge factor key
        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        return EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
    }

}
