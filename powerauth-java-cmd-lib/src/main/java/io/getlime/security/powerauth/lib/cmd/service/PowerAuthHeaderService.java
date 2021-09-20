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
package io.getlime.security.powerauth.lib.cmd.service;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Service for adding PowerAuth headers to requests
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Service
public class PowerAuthHeaderService {

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private static final PowerAuthClientSignature SIGNATURE = new PowerAuthClientSignature();

    private final StepLogger stepLogger;

    /**
     * Constructor
     *
     * @param stepLogger Step logger
     */
    @Autowired
    public PowerAuthHeaderService(StepLogger stepLogger) {
        this.stepLogger = stepLogger;
    }

    /**
     * Adds an encryption header to the request context
     * @param requestContext Request context
     * @param <T> Generic model type
     */
    public <T extends EncryptionHeaderData> void addEncryptionHeader(RequestContext requestContext, T model) {
        String activationId = model.getResultStatus().getActivationId();
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.getHttpHeaders().put(PowerAuthEncryptionHttpHeader.HEADER_NAME, headerValue);
    }

    /**
     * Adds a signature header to the request context
     * @param <M> Model type
     * @param <R> Response type
     * @param stepContext Step context
     * @throws Exception when an error during adding of a signature header occurred
     */
    public <M extends SignatureHeaderData, R> void addSignatureHeader(StepContext<M, R> stepContext) throws Exception {
        M model = stepContext.getModel();
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
        byte[] ctrData = CounterUtil.getCtrData(resultStatusObject, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion().value());

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
        String signatureValue = SIGNATURE.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), signatureSecretKeys, ctrData, signatureFormat);

        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(resultStatusObject.getActivationId(), model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion().value());

        Map<String, String> lowLevelData = new HashMap<>();
        lowLevelData.put("counter", String.valueOf(resultStatusObject.getCounter()));
        int version = resultStatusObject.getVersion().intValue();
        if (version == 3) {
            lowLevelData.put("ctrData", BaseEncoding.base64().encode(ctrData));
        }
        lowLevelData.put("signatureBaseString", signatureBaseString);
        lowLevelData.put("nonce", BaseEncoding.base64().encode(nonceBytes));
        lowLevelData.put("applicationSecret", model.getApplicationSecret());

        if (model instanceof VerifySignatureStepModel) {
            lowLevelData.put("activationId", resultStatusObject.getActivationId());
            lowLevelData.put("applicationKey", model.getApplicationKey());
            lowLevelData.put("resourceId", ((VerifySignatureStepModel) model).getResourceId());
            lowLevelData.put("serverPublicKey", resultStatusObject.getServerPublicKey());
            lowLevelData.put("transportKey", resultStatusObject.getTransportMasterKey());
        }

        stepLogger.writeItem(
                stepContext.getStep().id() + "-prepare-request",
                "Signature Calculation Parameters",
                "Low level cryptographic inputs required to compute signature - mainly a signature base string and a counter value.",
                "OK",
                lowLevelData
        );

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.getHttpHeaders().put(PowerAuthSignatureHttpHeader.HEADER_NAME, headerValue);
    }

    /**
     * Adds a token header to the request context
     * @param requestContext Request context
     * @param <T> Generic model type
     */
    public <T extends TokenHeaderData> void addTokenHeader(RequestContext requestContext, T model) throws Exception {
        String tokenId = model.getTokenId();
        byte[] tokenSecret = BaseEncoding.base64().decode(model.getTokenSecret());

        ClientTokenGenerator tokenGenerator = new ClientTokenGenerator();
        final byte[] tokenNonce = tokenGenerator.generateTokenNonce();
        final byte[] tokenTimestamp = tokenGenerator.generateTokenTimestamp();
        final byte[] tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, tokenSecret);

        PowerAuthTokenHttpHeader header = new PowerAuthTokenHttpHeader(
                tokenId,
                BaseEncoding.base64().encode(tokenDigest),
                BaseEncoding.base64().encode(tokenNonce),
                new String(tokenTimestamp, StandardCharsets.UTF_8),
                model.getVersion().value()
        );

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.getHttpHeaders().put(PowerAuthTokenHttpHeader.HEADER_NAME, headerValue);
    }

    private <M extends SignatureHeaderData> SecretKey getSignatureKnowledgeKey(M model) throws Exception {
        byte[] signatureKnowledgeKeySalt = model.getResultStatus().getSignatureKnowledgeKeySaltBytes();
        byte[] signatureKnowledgeKeyEncryptedBytes = model.getResultStatus().getSignatureKnowledgeKeyEncryptedBytes();

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (model.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = model.getPassword().toCharArray();
        }

        return EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
    }

}
