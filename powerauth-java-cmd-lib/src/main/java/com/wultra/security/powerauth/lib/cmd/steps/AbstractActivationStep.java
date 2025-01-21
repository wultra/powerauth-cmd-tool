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
package com.wultra.security.powerauth.lib.cmd.steps;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.ActivationSecurityContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import com.wultra.security.powerauth.rest.api.model.request.ActivationLayer2Request;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.response.ActivationLayer1Response;
import com.wultra.security.powerauth.rest.api.model.response.ActivationLayer2Response;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.TEMPORARY_KEY_ID;
import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.TEMPORARY_PUBLIC_KEY;

/**
 * Abstract step with common parts used in activations steps
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public abstract class AbstractActivationStep<M extends ActivationData> extends AbstractBaseStep<M, EciesEncryptedResponse> {

    private static final PowerAuthClientActivation ACTIVATION = new PowerAuthClientActivation();

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

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
        final ActivationSecurityContext securityContext = (ActivationSecurityContext) context.getSecurityContext();

        // Decrypt activation layer 1 response
        final byte[] decryptedDataL1 = securityContext.getEncryptorL1().decryptResponse(new EncryptedResponse(
                encryptedResponseL1.getEncryptedData(),
                encryptedResponseL1.getMac(),
                encryptedResponseL1.getNonce(),
                encryptedResponseL1.getTimestamp()
        ));

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
        EciesEncryptedResponse encryptedResponseL2 = responseL1.getActivationData();
        byte[] decryptedDataL2 = securityContext.getEncryptorL2().decryptResponse(new EncryptedResponse(
                encryptedResponseL2.getEncryptedData(),
                encryptedResponseL2.getMac(),
                encryptedResponseL2.getNonce(),
                encryptedResponseL2.getTimestamp()
        ));

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
     * @throws Exception when an error during encryption of the request data occurred
     */
    protected void addEncryptedRequest(StepContext<M, EciesEncryptedResponse> stepContext) throws Exception {
        M model = stepContext.getModel();
        fetchTemporaryKey(stepContext, EncryptorScope.APPLICATION_SCOPE);

        final String temporaryPublicKey = (String) stepContext.getAttributes().get(TEMPORARY_PUBLIC_KEY);
        final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                model.getMasterPublicKey() :
                KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(temporaryPublicKey));
        // Get activation key and secret
        ClientEncryptor clientEncryptorL1 = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                new ClientEncryptorSecrets(encryptionPublicKey, model.getApplicationSecret())
        );
        ClientEncryptor clientEncryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                new ClientEncryptorSecrets(encryptionPublicKey, model.getApplicationSecret())
        );

        KeyPair deviceKeyPair = ACTIVATION.generateDeviceKeyPair();

        ActivationSecurityContext securityContext = ActivationSecurityContext.builder()
                .encryptorL1(clientEncryptorL1)
                .encryptorL2(clientEncryptorL2)
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

        // Encrypt request data using ECIES in application scope with sharedInfo1 = /pa/activation
        EncryptedRequest encryptedRequestL2 = SecurityUtil.encryptObject(clientEncryptorL2, requestL2);

        // Prepare the encrypted layer 2 request
        EciesEncryptedRequest encryptedObjectL2 = SecurityUtil.createEncryptedRequest(encryptedRequestL2);

        // Prepare activation layer 1 request which is decryptable on intermediate server
        ActivationLayer1Request requestL1 = prepareLayer1Request(stepContext, encryptedObjectL2);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-request-encrypt",
                "Building activation request object",
                "Following activation attributes will be encrypted and sent to the server",
                "OK",
                requestL1
        );

        // Encrypt the layer 1 request using ECIES in application scope with sharedInfo1 = /pa/generic/application
        EncryptedRequest encryptedRequestL1 = SecurityUtil.encryptObject(clientEncryptorL1, requestL1);

        // Prepare the encrypted layer 1 request
        EciesEncryptedRequest encryptedRequestObjectL1 = SecurityUtil.createEncryptedRequest(encryptedRequestL1);

        stepContext.getRequestContext().setRequestObject(encryptedRequestObjectL1);
    }

}
