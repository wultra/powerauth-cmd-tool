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
package io.getlime.security.powerauth.lib.cmd.steps;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.ActivationSecurityContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptionUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.SecurityUtil;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

/**
 * Abstract step with common parts used in activations steps
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public abstract class AbstractActivationStep<M extends ActivationData> extends AbstractBaseStep<M, EciesEncryptedResponse> {

    private static final PowerAuthClientActivation ACTIVATION = new PowerAuthClientActivation();

    private static final EciesFactory ECIES_FACTORY = new EciesFactory();

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private static final PowerAuthClientVault VAULT = new PowerAuthClientVault();

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
    public void processResponse(StepContext<M, EciesEncryptedResponse> stepContext) throws Exception {
        EciesEncryptedResponse encryptedResponseL1 = stepContext.getResponseContext().getResponseBodyObject();
        M model = stepContext.getModel();
        ActivationSecurityContext securityContext = (ActivationSecurityContext) stepContext.getSecurityContext();

        ResultStatusObject resultStatusObject = processResponse(encryptedResponseL1, stepContext);
        model.setResultStatus(resultStatusObject);

        resultStatusService.save(model);

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("activationStatusFile", model.getStatusFileName());
        objectMap.put("activationStatusFileContent", model.getResultStatus());
        objectMap.put("deviceKeyFingerprint", ACTIVATION.computeActivationFingerprint(securityContext.getDeviceKeyPair().getPublic(), resultStatusObject.getServerPublicKeyObject(), resultStatusObject.getActivationId()));
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-custom-activation-done",
                "Activation Done",
                "Public key exchange was successfully completed, commit the activation on server if required",
                "OK",
                objectMap
        );
    }

    /**
     * Processes response and updates the activation status object
     *
     * @param encryptedResponseL1 Encrypted response from layer 1
     * @param context             Sterp context
     * @return Activation status object
     * @throws Exception when an error during response processing occurred
     */
    public ResultStatusObject processResponse(EciesEncryptedResponse encryptedResponseL1,
                                              StepContext<M, EciesEncryptedResponse> context) throws Exception {
        M model = context.getModel();
        ActivationSecurityContext securityContext = (ActivationSecurityContext) context.getSecurityContext();

        // Read activation layer 1 response and decrypt it
        byte[] ephemeralPublicKeyL1 = Base64.getDecoder().decode(encryptedResponseL1.getEphemeralPublicKey());
        byte[] macL1 = Base64.getDecoder().decode(encryptedResponseL1.getMac());
        byte[] encryptedDataL1 = Base64.getDecoder().decode(encryptedResponseL1.getEncryptedData());
        byte[] nonceL1 = encryptedResponseL1.getNonce() != null ? Base64.getDecoder().decode(encryptedResponseL1.getNonce()) : null;
        String applicationKey = context.getModel().getApplicationKey();
        final byte[] associatedDataL1 = context.getModel().getVersion().useTimestamp() ? EncryptionUtil.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, model.getVersion(), applicationKey, null) : null;

        Long timestampL1 = encryptedResponseL1.getTimestamp();

        EciesCryptogram responseCryptogramL1 = new EciesCryptogram(ephemeralPublicKeyL1, macL1, encryptedDataL1);
        EciesParameters eciesParametersL1 = new EciesParameters(nonceL1, associatedDataL1, timestampL1);
        EciesPayload eciesPayloadL1 = new EciesPayload(responseCryptogramL1, eciesParametersL1);
        String applicationSecret = context.getModel().getApplicationSecret();
        EciesEncryptor encryptor = securityContext.getEncryptorL1();
        EciesDecryptor eciesDecryptorL1 = ECIES_FACTORY.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                encryptor.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), null,
                eciesParametersL1, responseCryptogramL1.getEphemeralPublicKey());

        byte[] decryptedDataL1 = eciesDecryptorL1.decrypt(eciesPayloadL1);

        // Read activation layer 1 response from data
        ActivationLayer1Response responseL1 = MAPPER.readValue(decryptedDataL1, ActivationLayer1Response.class);

        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Layer 1 Response",
                "Following layer 1 activation data were decrypted",
                "OK",
                responseL1
        );

        // Decrypt layer 2 response
        byte[] ephemeralPublicKeyL2 = Base64.getDecoder().decode(responseL1.getActivationData().getEphemeralPublicKey());
        byte[] macL2 = Base64.getDecoder().decode(responseL1.getActivationData().getMac());
        byte[] encryptedDataL2 = Base64.getDecoder().decode(responseL1.getActivationData().getEncryptedData());
        byte[] nonceL2 = responseL1.getActivationData().getNonce() != null ? Base64.getDecoder().decode(responseL1.getActivationData().getNonce()) : null;
        final byte[] associatedDataL2 = context.getModel().getVersion().useTimestamp() ? EncryptionUtil.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, model.getVersion(), applicationKey, null) : null;
        Long timestampL2 = responseL1.getActivationData().getTimestamp();

        EciesCryptogram responseCryptogramL2 = new EciesCryptogram(ephemeralPublicKeyL2, macL2, encryptedDataL2);
        EciesParameters eciesParametersL2 = new EciesParameters(nonceL2, associatedDataL2, timestampL2);
        EciesPayload responsePayloadL2 = new EciesPayload(responseCryptogramL2, eciesParametersL2);
        EciesEncryptor encryptorL2 = securityContext.getEncryptorL2();
        EciesDecryptor eciesDecryptorL2 = ECIES_FACTORY.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                encryptorL2.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), null,
                eciesParametersL2, responseCryptogramL2.getEphemeralPublicKey());
        byte[] decryptedDataL2 = eciesDecryptorL2.decrypt(responsePayloadL2);

        // Convert activation layer 2 response from JSON to object and extract activation parameters
        ActivationLayer2Response responseL2 = MAPPER.readValue(decryptedDataL2, ActivationLayer2Response.class);

        context.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt-inner",
                "Decrypted Layer 2 Response",
                "Following layer 2 activation data were decrypted",
                "OK",
                responseL2
        );

        String activationId = responseL2.getActivationId();
        String ctrDataBase64 = responseL2.getCtrData();
        String serverPublicKeyBase64 = responseL2.getServerPublicKey();
        PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(serverPublicKeyBase64));

        // Compute master secret key
        SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(securityContext.getDeviceKeyPair().getPrivate(), serverPublicKey);

        // Derive PowerAuth keys from master secret key
        SecretKey signaturePossessionSecretKey = KEY_FACTORY.generateClientSignaturePossessionKey(masterSecretKey);
        SecretKey signatureKnowledgeSecretKey = KEY_FACTORY.generateClientSignatureKnowledgeKey(masterSecretKey);
        SecretKey signatureBiometrySecretKey = KEY_FACTORY.generateClientSignatureBiometryKey(masterSecretKey);
        SecretKey transportMasterKey = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
        // DO NOT EVER STORE ...
        SecretKey vaultUnlockMasterKey = KEY_FACTORY.generateServerEncryptedVaultKey(masterSecretKey);

        // Encrypt the original device private key using the vault unlock key
        byte[] encryptedDevicePrivateKey = VAULT.encryptDevicePrivateKey(securityContext.getDeviceKeyPair().getPrivate(), vaultUnlockMasterKey);

        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        byte[] cSignatureKnowledgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnowledgeSecretKey, salt, KEY_GENERATOR);

        ResultStatusObject resultStatusObject = model.getResultStatus();

        resultStatusObject.setActivationId(activationId);
        resultStatusObject.setCounter(0L);
        resultStatusObject.setCtrData(ctrDataBase64);
        resultStatusObject.setEncryptedDevicePrivateKeyBytes(encryptedDevicePrivateKey);
        resultStatusObject.setServerPublicKeyObject(serverPublicKey);
        resultStatusObject.setSignatureBiometryKeyObject(signatureBiometrySecretKey);
        resultStatusObject.setSignatureKnowledgeKeyEncryptedBytes(cSignatureKnowledgeSecretKey);
        resultStatusObject.setSignatureKnowledgeKeySaltBytes(salt);
        resultStatusObject.setSignaturePossessionKeyObject(signaturePossessionSecretKey);
        resultStatusObject.setTransportMasterKeyObject(transportMasterKey);
        resultStatusObject.setVersion(3L);

        return resultStatusObject;
    }

    /**
     * Prepare activation layer 1 request which is decryptable on an intermediate server
     *
     * @param stepContext        Step context
     * @param encryptedRequestL2 Encrypted request from layer 2
     * @return Layer 1 request
     */
    protected abstract ActivationLayer1Request prepareLayer1Request(StepContext<M, EciesEncryptedResponse> stepContext, EciesEncryptedRequest encryptedRequestL2);

    /**
     * @return Type reference of the response object
     */
    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    /**
     * Prepares ECIES encryptors and encrypts request data.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext Step context
     * @param version Protocol version
     * @throws Exception when an error during encryption of the request data occurred
     */
    protected void addEncryptedRequest(StepContext<M, EciesEncryptedResponse> stepContext, PowerAuthVersion version) throws Exception {
        M model = stepContext.getModel();

        // Get activation key and secret
        final byte[] applicationKey = model.getApplicationKey().getBytes(StandardCharsets.UTF_8);
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

        final Long timestamp = version.useTimestamp() ? new Date().getTime() : null;
        final byte[] associatedData = version.useTimestamp() ? EncryptionUtil.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, version, new String(applicationKey, StandardCharsets.UTF_8), null) : null;
        final byte[] nonceBytesL1 = version.useIv() ? new KeyGenerator().generateRandomBytes(16) : null;
        final byte[] nonceBytesL2 = version.useIv() ? new KeyGenerator().generateRandomBytes(16) : null;
        final EciesParameters eciesParametersL1 = EciesParameters.builder().nonce(nonceBytesL1).associatedData(associatedData).timestamp(timestamp).build();
        final EciesParameters eciesParametersL2 = EciesParameters.builder().nonce(nonceBytesL2).associatedData(associatedData).timestamp(timestamp).build();

        EciesEncryptor eciesEncryptorL1 = ECIES_FACTORY.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC, eciesParametersL1);
        EciesEncryptor eciesEncryptorL2 = ECIES_FACTORY.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2, eciesParametersL2);

        KeyPair deviceKeyPair = ACTIVATION.generateDeviceKeyPair();

        ActivationSecurityContext securityContext = ActivationSecurityContext.builder()
                .encryptorL1(eciesEncryptorL1)
                .encryptorL2(eciesEncryptorL2)
                .deviceKeyPair(deviceKeyPair)
                .build();
        stepContext.setSecurityContext(securityContext);

        // Read the identity attributes and custom attributes
        Map<String, String> identityAttributes = model.getIdentityAttributes();
        if (identityAttributes != null && !identityAttributes.isEmpty()) {
            stepContext.getStepLogger().writeItem(
                    getStep().id() + "-identity-attributes",
                    "Identity Attributes",
                    "Following attributes are used to authenticate user",
                    "OK",
                    identityAttributes
            );
        }

        Map<String, Object> customAttributes = model.getCustomAttributes();
        if (customAttributes != null && !customAttributes.isEmpty()) {
            stepContext.getStepLogger().writeItem(
                    getStep().id() + "-custom-attributes",
                    "Custom Attributes",
                    "Following attributes are used as custom attributes for the request",
                    "OK",
                    customAttributes
            );
        }

        // Generate device key pair
        byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(securityContext.getDeviceKeyPair().getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);

        // Create activation layer 2 request which is decryptable only on PowerAuth server
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(model.getActivationName());
        if (model instanceof PrepareActivationStepModel) {
            requestL2.setActivationOtp(((PrepareActivationStepModel) model).getAdditionalActivationOtp());
        }
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        requestL2.setPlatform(model.getPlatform());
        requestL2.setDeviceInfo(model.getDeviceInfo());

        final boolean useIv = model.getVersion().useIv();
        final boolean useTimestamp = model.getVersion().useTimestamp();

        // Encrypt request data using ECIES in application scope with sharedInfo1 = /pa/activation
        final byte[] associatedDataL2 = useTimestamp ? EncryptionUtil.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, version, new String(applicationKey, StandardCharsets.UTF_8), null) : null;
        EciesPayload eciesPayloadL2 = SecurityUtil.encryptObject(securityContext.getEncryptorL2(), requestL2, useIv, useTimestamp, associatedDataL2);

        // Prepare the encrypted layer 2 request
        EciesEncryptedRequest encryptedRequestL2 = SecurityUtil.createEncryptedRequest(eciesPayloadL2, useIv, useTimestamp);

        // Prepare activation layer 1 request which is decryptable on intermediate server
        ActivationLayer1Request requestL1 = prepareLayer1Request(stepContext, encryptedRequestL2);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-request-encrypt",
                "Building activation request object",
                "Following activation attributes will be encrypted and sent to the server",
                "OK",
                requestL1
        );

        // Encrypt the layer 1 request using ECIES in application scope with sharedInfo1 = /pa/generic/application
        EciesPayload eciesPayloadL1 = SecurityUtil.encryptObject(securityContext.getEncryptorL1(), requestL1, useIv, useTimestamp, associatedData);

        // Prepare the encrypted layer 1 request
        EciesEncryptedRequest encryptedRequestL1 = SecurityUtil.createEncryptedRequest(eciesPayloadL1, useIv, useTimestamp);

        stepContext.getRequestContext().setRequestObject(encryptedRequestL1);
    }

}
