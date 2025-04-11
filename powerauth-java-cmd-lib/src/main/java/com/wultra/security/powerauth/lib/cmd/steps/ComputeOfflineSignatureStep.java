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
package com.wultra.security.powerauth.lib.cmd.steps;

import com.wultra.security.powerauth.crypto.lib.config.SignatureConfiguration;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.ComputeOfflineSignatureStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Step for computing offline PowerAuth signature.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ComputeOfflineSignatureStep extends AbstractBaseStep<ComputeOfflineSignatureStepModel, Void> {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    /**
     * Constructor
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public ComputeOfflineSignatureStep(
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.SIGNATURE_OFFLINE_COMPUTE, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);
    }

    /**
     * Constructor for backward compatibility
     */
    public ComputeOfflineSignatureStep() {
        this(
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public ParameterizedTypeReference<Void> getResponseTypeReference(PowerAuthVersion version) {
        // No response type, server is not called due to offline nature of the step
        return null;
    }

    @Override
    public StepContext<ComputeOfflineSignatureStepModel, Void> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final ComputeOfflineSignatureStepModel model = new ComputeOfflineSignatureStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString())
                .build();

        final StepContext<ComputeOfflineSignatureStepModel, Void> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        if (model.getQrCodeData() == null) {
            stepLogger.writeError(getStep().id() + "-error-missing-qr-code-data", "Missing offline signature data", "Specify offline signature data which is encoded in QR code");
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }

        final String offlineData = unescape(model.getQrCodeData());
        final Map<String, String> inputMap = new HashMap<>();
        inputMap.put("qrCodeData", offlineData);

        stepLogger.writeItem(
                getStep().id() + "-start",
                "Offline Signature Computation Started",
                null,
                "OK",
                inputMap
        );

        // Ask for the password to unlock knowledge factor key
        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        final String offlineSignature = calculateOfflineSignature(offlineData, stepLogger, model.getResultStatus(), password);
        if (offlineSignature == null) {
            return null;
        }

        final Map<String, String> resultMap = new HashMap<>();
        resultMap.put("offlineSignature", offlineSignature);

        stepLogger.writeItem(
                getStep().id() + "-finished",
                "Offline Signature Computation Finished",
                null,
                "OK",
                resultMap
        );

        incrementCounter(stepContext.getModel());

        return stepContext;
    }

    private String unescape(String text) {
        return text.replace("\\n", "\n");
    }

    private String calculateOfflineSignature(final String offlineData, final StepLogger stepLogger,
                                             final ResultStatusObject resultStatusObject, final char[] password) {
        // Split the offline data into individual lines, see: https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md
        final String[] parts = offlineData.split("\n");
        if (parts.length < 7) {
            stepLogger.writeError(getStep().id() + "-error-invalid-qr-code-data", "Invalid QR code data", "Invalid QR code, expected 7 lines of data or more");
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }
        final String operationId = parts[0];
        final String operationData = parts[3];
        final String nonce = parts[parts.length - 2];
        final String signatureLine = parts[parts.length - 1];
        final String totp = (parts.length > 7 && parts[parts.length - 3].matches("^[0-9]+$")) ? parts[parts.length - 3] : null;

        // 1 = KEY_SERVER_PRIVATE was used to sign data (personalized offline signature), otherwise return error
        final String signatureType = signatureLine.substring(0, 1);
        if (!"1".equals(signatureType)) {
            stepLogger.writeError(getStep().id() + "-error-invalid-signature-type", "Invalid signature type", "Personalized offline signature expected, however other signature type is used");
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }

        try {
            // Verify ECDSA signature from the offline data, return error in case of invalid signature
            final String ecdsaSignature = signatureLine.substring(1);
            final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(resultStatusObject.getEcServerPublicKey());
            final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
            final String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());
            final boolean dataSignatureValid = SIGNATURE_UTILS.validateECDSASignature(
                    offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8),
                    Base64.getDecoder().decode(ecdsaSignature),
                    serverPublicKey);
            if (!dataSignatureValid) {
                stepLogger.writeError(getStep().id() + "-error-invalid-signature", "Invalid signature", "Invalid signature of offline data");
                stepLogger.writeDoneFailed(getStep().id() + "-failed");
                return null;
            }

            // Prepare data for PowerAuth offline signature calculation
            final String dataForSignature = Stream.of(operationId, operationData, totp)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.joining("&"));
            final String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString(
                    "POST",
                    "/operation/authorize/offline",
                    Base64.getDecoder().decode(nonce),
                    dataForSignature.getBytes(StandardCharsets.UTF_8));

            // Prepare keys for PowerAuth offline signature calculation
            final byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(resultStatusObject.getSignaturePossessionKey());
            final byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(resultStatusObject.getSignatureKnowledgeKeySalt());
            final byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(resultStatusObject.getSignatureKnowledgeKeyEncrypted());
            final SecretKey signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
            final SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(
                    password,
                    signatureKnowledgeKeyEncryptedBytes,
                    signatureKnowledgeKeySalt,
                    KEY_GENERATOR);
            final List<SecretKey> signatureKeys = new ArrayList<>();
            signatureKeys.add(signaturePossessionKey);
            signatureKeys.add(signatureKnowledgeKey);

            // Calculate signature of normalized signature base string with 'offline' constant used as application secret
            return SIGNATURE_UTILS.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8),
                    signatureKeys,
                    CounterUtil.getCtrData(resultStatusObject, stepLogger),
                    SignatureConfiguration.decimal());
        } catch (Exception ex) {
            stepLogger.writeError(getStep().id() + "-error-cryptography", "Cryptography error", ex.getMessage());
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }
    }
}
