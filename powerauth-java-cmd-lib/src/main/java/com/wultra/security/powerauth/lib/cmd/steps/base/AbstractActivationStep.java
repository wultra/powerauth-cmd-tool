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
package com.wultra.security.powerauth.lib.cmd.steps.base;

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.ActivationSecurityContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.KeyDerivationUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.lib.cmd.util.SharedSecretUtil;
import com.wultra.security.powerauth.rest.api.model.request.v4.DevicePublicKeys;
import com.wultra.security.powerauth.rest.api.model.request.v4.SharedSecretRequest;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerPublicKeys;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import org.springframework.core.ParameterizedTypeReference;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Abstract step with common parts used in activations steps
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public abstract class AbstractActivationStep<M extends ActivationData> extends AbstractBaseStep<M, EncryptedResponse> {

    private static final com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation CLIENT_ACTIVATION_V3 = new com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation();
    private static final com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation CLIENT_ACTIVATION_V4 = new com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation();

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    private static final ObjectMapper MAPPER = RestClientConfiguration.defaultMapper();

    /**
     * Constructor
     *
     * @param step                Corresponding PowerAuth step
     * @param supportedVersions   Supported versions of PowerAuth
     * @param resultStatusService Result status service
     * @param stepLoggerFactory   Step logger factory
     */
    public AbstractActivationStep(PowerAuthStep step,
                                  List<PowerAuthVersion> supportedVersions,
                                  ResultStatusService resultStatusService,
                                  StepLoggerFactory stepLoggerFactory) {
        super(step, supportedVersions, resultStatusService, stepLoggerFactory);
    }

    /**
     * Processes the response data
     *
     * @param stepContext Step context
     * @throws Exception when an error during response processing occurred
     */
    @Override
    public void processResponse(StepContext<M, EncryptedResponse> stepContext) throws Exception {
        final EncryptedResponse encryptedResponseL1 = stepContext.getResponseContext().getResponseBodyObject();
        final M model = stepContext.getModel();
        final ActivationSecurityContext securityContext = (ActivationSecurityContext) stepContext.getSecurityContext();

        final ResultStatusObject resultStatusObject = processResponse(encryptedResponseL1, stepContext);
        model.setResultStatus(resultStatusObject);

        resultStatusService.save(model);

        final Map<String, Object> objectMap = new LinkedHashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("activationStatusFile", model.getStatusFileName());
        objectMap.put("activationStatusFileContent", model.getResultStatus());
        objectMap.put("deviceKeyFingerprint", computeActivationFingerprint(model.getVersion().getMajorVersion(), securityContext, resultStatusObject));

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-activation-done",
                "Activation Done",
                "Public key exchange was successfully completed, commit the activation on server if required",
                "OK",
                objectMap
        );
    }

    private String computeActivationFingerprint(int majorVersion, ActivationSecurityContext securityContext, ResultStatusObject resultStatusObject) throws Exception {
        return switch (majorVersion) {
            case 3 -> CLIENT_ACTIVATION_V3.computeActivationFingerprint(
                    securityContext.getEcDeviceKeyPair().getPublic(),
                    resultStatusObject.getEcServerPublicKeyObject(),
                    resultStatusObject.getActivationId()
            );
            case 4 -> switch (securityContext.getSharedSecretAlgorithm()) {
                case EC_P384 -> CLIENT_ACTIVATION_V4.computeActivationEcFingerprint(
                        securityContext.getEcDeviceKeyPair().getPublic(),
                        resultStatusObject.getEcServerPublicKeyObject(),
                        resultStatusObject.getActivationId()
                );
                case EC_P384_ML_L3, EC_P384_ML_L5 -> CLIENT_ACTIVATION_V4.computeActivationHybridFingerprint(
                        securityContext.getSharedSecretAlgorithm(),
                        securityContext.getEcDeviceKeyPair().getPublic(),
                        securityContext.getPqcDeviceKeyPair().getPublic(),
                        resultStatusObject.getEcServerPublicKeyObject(),
                        resultStatusObject.getPqcServerPublicKeyObject(),
                        resultStatusObject.getActivationId()
                );
                default -> throw new IllegalStateException("Unsupported shared secret algorithm: " + securityContext.getSharedSecretAlgorithm());
            };
            default -> throw new IllegalStateException("Unsupported version: " + majorVersion);
        };
    }

    /**
     * Processes response and updates the activation status object
     *
     * @param encryptedResponseL1 Encrypted response from layer 1
     * @param context             Sterp context
     * @return Activation status object
     * @throws Exception when an error during response processing occurred
     */
    public ResultStatusObject processResponse(EncryptedResponse encryptedResponseL1, StepContext<M, EncryptedResponse> context) throws Exception {
        return switch (context.getModel().getVersion().getMajorVersion()) {
            case 3 -> processActivationResponseV3(encryptedResponseL1, context);
            case 4 -> processActivationResponseV4(encryptedResponseL1, context);
            default -> throw new IllegalStateException("Unsupported version: " + context.getModel().getVersion());
        };
    }

    private ResultStatusObject processActivationResponseV3(EncryptedResponse encryptedResponseL1, StepContext<M, EncryptedResponse> context) throws Exception {
        final M model = context.getModel();
        final ActivationSecurityContext securityContext = (ActivationSecurityContext) context.getSecurityContext();
        final EciesEncryptedResponse eciesResponseL1 = (EciesEncryptedResponse) encryptedResponseL1;
        final ResultStatusObject resultStatusObject = model.getResultStatus();
        final byte[] decryptedDataL1 = securityContext.getEncryptorL1().decryptResponse(new EciesEncryptedResponse(
                eciesResponseL1.getEncryptedData(),
                eciesResponseL1.getMac(),
                eciesResponseL1.getNonce(),
                eciesResponseL1.getTimestamp()
        ));
        final com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response responseL1V3 = MAPPER.readValue(decryptedDataL1, com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response.class);
        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Layer 1 Response",
                "Following layer 1 activation data were decrypted",
                "OK",
                responseL1V3
        );
        final EciesEncryptedResponse eciesResponseL2 = responseL1V3.getActivationData();
        final byte[] decryptedDataL2 = securityContext.getEncryptorL2().decryptResponse(new EciesEncryptedResponse(
                eciesResponseL2.getEncryptedData(),
                eciesResponseL2.getMac(),
                eciesResponseL2.getNonce(),
                eciesResponseL2.getTimestamp()
        ));
        // Convert activation layer 2 response from JSON to object and extract activation parameters
        final com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response responseL2 = MAPPER.readValue(decryptedDataL2, com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response.class);

        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt-inner",
                "Decrypted Layer 2 Response",
                "Following layer 2 activation data were decrypted",
                "OK",
                responseL2
        );

        final String activationId = responseL2.getActivationId();
        final String ctrDataBase64 = responseL2.getCtrData();
        final String serverPublicKeyBase64 = responseL2.getServerPublicKey();
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(serverPublicKeyBase64));

        resultStatusObject.setVersion(3L);
        resultStatusObject.setActivationId(activationId);
        resultStatusObject.setCounter(0L);
        resultStatusObject.setCtrData(ctrDataBase64);
        resultStatusObject.setSharedSecretAlgorithm(securityContext.getSharedSecretAlgorithm().toString());

        KeyDerivationUtil.deriveKeysV3(resultStatusObject, serverPublicKey, securityContext.getEcDeviceKeyPair(), model.getPassword());

        return resultStatusObject;
    }

    private ResultStatusObject processActivationResponseV4(EncryptedResponse encryptedResponseL1, StepContext<M, EncryptedResponse> context) throws Exception {
        final M model = context.getModel();
        final ActivationSecurityContext securityContext = (ActivationSecurityContext) context.getSecurityContext();
        final ResultStatusObject resultStatusObject = model.getResultStatus();
        final AeadEncryptedResponse aeadResponseL1 = (AeadEncryptedResponse) encryptedResponseL1;
        final byte[] decryptedDataL1 = securityContext.getEncryptorL1().decryptResponse(new AeadEncryptedResponse(
                aeadResponseL1.getEncryptedData(),
                aeadResponseL1.getTimestamp()
        ));
        final com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer1Response responseL1V4 = MAPPER.readValue(decryptedDataL1, com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer1Response.class);
        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Layer 1 Response",
                "Following layer 1 activation data were decrypted",
                "OK",
                responseL1V4
        );
        final AeadEncryptedResponse aeadResponseL2 = responseL1V4.getActivationData();
        final byte[] decryptedDataL2 = securityContext.getEncryptorL2().decryptResponse(new AeadEncryptedResponse(
                aeadResponseL2.getEncryptedData(),
                aeadResponseL2.getTimestamp()
        ));

        final SharedSecretClientContext clientContext = securityContext.getSharedSecretClientContext();
        // Convert activation layer 2 response from JSON to object and extract activation parameters
        final com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer2Response responseL2 = MAPPER.readValue(decryptedDataL2, com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer2Response.class);
        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt-inner",
                "Decrypted Layer 2 Response",
                "Following layer 2 activation data were decrypted",
                "OK",
                responseL2
        );

        final String activationId = responseL2.getActivationId();
        final String ctrDataBase64 = responseL2.getCtrData();
        final ServerPublicKeys serverPublicKeys = responseL2.getServerPublicKeys();
        final SharedSecretResponse sharedSecretResponse = responseL2.getSharedSecretResponse();
        final SecretKey activationSharedSecret = SharedSecretUtil.deriveSharedSecret(sharedSecretResponse, clientContext, model.getSharedSecretAlgorithm());

        resultStatusObject.setVersion(4L);
        resultStatusObject.setActivationId(activationId);
        resultStatusObject.setCounter(0L);
        resultStatusObject.setCtrData(ctrDataBase64);
        resultStatusObject.setSharedSecretAlgorithm(securityContext.getSharedSecretAlgorithm().toString());

        KeyDerivationUtil.deriveKeysV4(activationSharedSecret, resultStatusObject, serverPublicKeys, securityContext.getEcDeviceKeyPair(), securityContext.getPqcDeviceKeyPair(), model.getPassword());

        return resultStatusObject;
    }

    /**
     * Prepare activation layer 1 request which is decryptable on an intermediate server
     *
     * @param stepContext        Step context
     * @param encryptedRequestL2 Encrypted request from layer 2
     * @return Layer 1 request
     */
    protected abstract Object prepareLayer1Request(StepContext<M, EncryptedResponse> stepContext, EncryptedRequest encryptedRequestL2);

    /**
     * @return Type reference of the response object
     */
    @Override
    protected ParameterizedTypeReference<EncryptedResponse> getResponseTypeReference(PowerAuthVersion version) {
        return getResponseTypeReferenceEncrypted(version);
    }

    /**
     * Prepares ECIES encryptors and encrypts request data.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext Step context
     * @throws Exception when an error during encryption of the request data occurred
     */
    protected void addEncryptedRequest(StepContext<M, EncryptedResponse> stepContext) throws Exception {
        final M model = stepContext.getModel();
        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.APPLICATION_SCOPE);
        boolean temporaryKeyFetchSucceeded = fetchTemporaryKey(stepContext, EncryptorScope.APPLICATION_SCOPE, sharedSecretAlgorithm);
        if (!temporaryKeyFetchSucceeded) {
            // Error is already logged
            return;
        }

        final KeyPair deviceKeyPair;
        final ActivationSecurityContext securityContext;
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptorL1;
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptorL2;
        final Object requestL2Object;
        switch (model.getVersion().getMajorVersion()) {
            case 3 -> {
                deviceKeyPair = CLIENT_ACTIVATION_V3.generateDeviceKeyPair();
                final PublicKey encryptionPublicKey;
                final String temporaryKeyId;
                if (model.getVersion().useTemporaryKeys()) {
                    final String temporaryPublicKey = stepContext.getTemporaryKeyContext().getTemporaryPublicKey();
                    temporaryKeyId = stepContext.getTemporaryKeyContext().getTemporaryKeyId();
                    encryptionPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(temporaryPublicKey));
                } else {
                    encryptionPublicKey = model.getMasterPublicKeyP256();
                    temporaryKeyId = null;
                }
                encryptorL1 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.APPLICATION_SCOPE_GENERIC,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId),
                        new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret())
                );
                encryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.ACTIVATION_LAYER_2,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId),
                        new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret())
                );
                securityContext = ActivationSecurityContext.builder()
                        .encryptorL1(encryptorL1)
                        .encryptorL2(encryptorL2)
                        .ecDeviceKeyPair(deviceKeyPair)
                        .sharedSecretAlgorithm(sharedSecretAlgorithm)
                        .build();
                final byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, securityContext.getEcDeviceKeyPair().getPublic());
                final String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
                com.wultra.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request requestL2 = new com.wultra.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request();
                requestL2.setActivationName(model.getActivationName());
                if (model instanceof PrepareActivationStepModel) {
                    requestL2.setActivationOtp(((PrepareActivationStepModel) model).getAdditionalActivationOtp());
                }
                requestL2.setDevicePublicKey(devicePublicKeyBase64);
                requestL2.setPlatform(model.getPlatform());
                requestL2.setDeviceInfo(model.getDeviceInfo());
                requestL2Object = requestL2;
            }
            case 4 -> {
                final SecretKey sharedSecret = stepContext.getTemporaryKeyContext().getTemporarySharedSecret();
                if (sharedSecret == null) {
                    stepContext.getStepLogger().writeError(getStep().id() + "-error-missing-temporary-shared-secret", "Temporary shared secret is missing", "Temporary shared secret was not derived when adding encrypted request");
                    return;
                }
                final String temporaryKeyId = stepContext.getTemporaryKeyContext().getTemporaryKeyId();
                if (temporaryKeyId == null) {
                    stepContext.getStepLogger().writeError(getStep().id() + "-error-missing-temporary-key-id", "Temporary key identifier is missing", "Temporary key identifier is missing when adding encrypted request");
                    return;
                }
                encryptorL1 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.APPLICATION_SCOPE_GENERIC,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId),
                        new AeadSecrets(sharedSecret.getEncoded(), model.getApplicationSecret())
                );
                encryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.ACTIVATION_LAYER_2,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId),
                        new AeadSecrets(sharedSecret.getEncoded(), model.getApplicationSecret())
                );

                final AtomicReference<SharedSecretClientContext> ctxRef = new AtomicReference<>();
                final SharedSecretRequest requestSharedSecret = SharedSecretUtil.buildSharedSecretRequest(
                        model.getSharedSecretAlgorithm(),
                        ctxRef::set
                );
                final SharedSecretClientContext clientContext = ctxRef.get();
                final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
                sharedSecretRequest.setAlgorithm(model.getSharedSecretAlgorithm().name());
                final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
                final KeyPair ecDeviceKeyPair = CLIENT_ACTIVATION_V4.generateDeviceEcKeyPair();
                final KeyPair pqcDeviceKeyPair;
                switch (model.getSharedSecretAlgorithm()) {
                    case EC_P384 -> {
                        final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                        final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                        devicePublicKeys.setEcdsa(ecPublicKeyBase64);
                        pqcDeviceKeyPair = null;

                        sharedSecretRequest.setEncapsulationKeys(List.of(requestSharedSecret.getEncapsulationKeys().get(0)));
                    }
                    case EC_P384_ML_L3, EC_P384_ML_L5 -> {
                        final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                        final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                        devicePublicKeys.setEcdsa(ecPublicKeyBase64);

                        pqcDeviceKeyPair = CLIENT_ACTIVATION_V4.generateDevicePqcKeyPair(sharedSecretAlgorithm);
                        final byte[] pqcPublicKeyBytes = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcDeviceKeyPair.getPublic());
                        final String pqcPublicKeyBase64 = Base64.getEncoder().encodeToString(pqcPublicKeyBytes);
                        devicePublicKeys.setMldsa(pqcPublicKeyBase64);

                        sharedSecretRequest.setEncapsulationKeys(List.of((requestSharedSecret.getEncapsulationKeys().get(0)), (requestSharedSecret.getEncapsulationKeys().get(1))));
                    }
                    default -> throw new IllegalStateException("Unsupported shared secret algorithm: " + model.getSharedSecretAlgorithm());
                }
                securityContext = ActivationSecurityContext.builder()
                        .encryptorL1(encryptorL1)
                        .encryptorL2(encryptorL2)
                        .ecDeviceKeyPair(ecDeviceKeyPair)
                        .pqcDeviceKeyPair(pqcDeviceKeyPair)
                        .sharedSecretAlgorithm(sharedSecretAlgorithm)
                        .sharedSecretClientContext(clientContext)
                        .build();

                com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer2Request requestL2 = new com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer2Request();
                requestL2.setActivationName(model.getActivationName());
                if (model instanceof PrepareActivationStepModel) {
                    requestL2.setActivationOtp(((PrepareActivationStepModel) model).getAdditionalActivationOtp());
                }
                requestL2.setSharedSecretRequest(sharedSecretRequest);
                requestL2.setDevicePublicKeys(devicePublicKeys);
                requestL2.setPlatform(model.getPlatform());
                requestL2.setDeviceInfo(model.getDeviceInfo());
                requestL2Object = requestL2;
            }
            default -> throw new IllegalStateException("Unsupported version: " + model.getVersion());
        }

        stepContext.setSecurityContext(securityContext);

        // Read the identity attributes and custom attributes
        final Map<String, String> identityAttributes = model.getIdentityAttributes();
        if (identityAttributes != null && !identityAttributes.isEmpty()) {
            stepContext.getStepLogger().writeItem(
                    getStep().id() + "-identity-attributes",
                    "Identity Attributes",
                    "Following attributes are used to authenticate user",
                    "OK",
                    identityAttributes
            );
        }

        final Map<String, Object> customAttributes = model.getCustomAttributes();
        if (customAttributes != null && !customAttributes.isEmpty()) {
            stepContext.getStepLogger().writeItem(
                    getStep().id() + "-custom-attributes",
                    "Custom Attributes",
                    "Following attributes are used as custom attributes for the request",
                    "OK",
                    customAttributes
            );
        }

        // Encrypt request in application scope with sharedInfo1 = /pa/activation
        final EncryptedRequest encryptedRequestL2 = SecurityUtil.encryptObject(encryptorL2, requestL2Object);

        // Prepare activation layer 1 request which is decryptable on intermediate server
        final Object requestL1 = prepareLayer1Request(stepContext, encryptedRequestL2);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-request-encrypt",
                "Building activation request object",
                "Following activation attributes will be encrypted and sent to the server",
                "OK",
                requestL1
        );

        // Encrypt the layer 1 request in application scope with sharedInfo1 = /pa/generic/application
        final EncryptedRequest encryptedRequestL1 = SecurityUtil.encryptObject(encryptorL1, requestL1);

        stepContext.getRequestContext().setRequestObject(encryptedRequestL1);
    }

}
