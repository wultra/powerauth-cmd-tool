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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
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
import com.wultra.security.powerauth.rest.api.model.request.v4.DevicePublicKeys;
import com.wultra.security.powerauth.rest.api.model.request.v4.SharedSecretRequest;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerPublicKeys;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.*;

/**
 * Abstract step with common parts used in activations steps
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public abstract class AbstractActivationStep<M extends ActivationData> extends AbstractBaseStep<M, EncryptedResponse> {

    private static final PowerAuthClientActivation ACTIVATION = new PowerAuthClientActivation();

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PqcDsa PQC_DSA = new PqcDsa();

    private static final PowerAuthClientVault VAULT = new PowerAuthClientVault();

    private static final ObjectMapper MAPPER = RestClientConfiguration.defaultMapper();

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

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

        final Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("activationStatusFile", model.getStatusFileName());
        objectMap.put("activationStatusFileContent", model.getResultStatus());
        objectMap.put("deviceKeyFingerprint", ACTIVATION.computeActivationFingerprint(securityContext.getEcDeviceKeyPair().getPublic(), resultStatusObject.getEcServerPublicKeyObject(), resultStatusObject.getActivationId()));
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-activation-done",
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

        // Compute master secret key
        final SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(securityContext.getEcDeviceKeyPair().getPrivate(), serverPublicKey);

        // Derive PowerAuth keys from master secret key
        final SecretKey possessionFactorKey = KEY_FACTORY.generateClientPossessionFactorKey(masterSecretKey);
        final SecretKey knowledgeFactorKey = KEY_FACTORY.generateClientKnowledgeFactorKey(masterSecretKey);
        final SecretKey biometryFactorKey = KEY_FACTORY.generateClientBiometryFactorKey(masterSecretKey);
        final SecretKey transportMasterKey = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
        // DO NOT EVER STORE ...
        final SecretKey vaultUnlockMasterKey = KEY_FACTORY.generateServerEncryptedVaultKey(masterSecretKey);

        // Encrypt the original device private key using the vault unlock key
        final byte[] encryptedDevicePrivateKey = VAULT.encryptDevicePrivateKey(securityContext.getEcDeviceKeyPair().getPrivate(), vaultUnlockMasterKey);

        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        final byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] cKnowledgeFactorSecretKey = EncryptedStorageUtil.storeKnowledgeFactorKey(password, knowledgeFactorKey, salt, KEY_GENERATOR);

        resultStatusObject.setVersion((long) model.getVersion().getMajorVersion());
        resultStatusObject.setActivationId(activationId);
        resultStatusObject.setCounter(0L);
        resultStatusObject.setCtrData(ctrDataBase64);
        resultStatusObject.setEncryptedDevicePrivateKeyBytes(encryptedDevicePrivateKey);
        resultStatusObject.setEcServerPublicKeyObject(serverPublicKey);
        resultStatusObject.setBiometryFactorKeyObject(biometryFactorKey);
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(cKnowledgeFactorSecretKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(salt);
        resultStatusObject.setPossessionFactorKeyObject(possessionFactorKey);
        resultStatusObject.setTransportMasterKeyObject(transportMasterKey);

        resultStatusObject.setSharedSecretAlgorithm(securityContext.getSharedSecretAlgorithm().toString());
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
        final com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer2Response responseL2 = MAPPER.readValue(decryptedDataL2, com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer2Response.class);
        final String activationId = responseL2.getActivationId();
        final String ctrDataBase64 = responseL2.getCtrData();
        final ServerPublicKeys serverPublicKeys = responseL2.getServerPublicKeys();
        final SharedSecretResponse sharedSecretResponse = responseL2.getSharedSecretResponse();
        final SecretKey activationSharedSecret;

        switch (model.getSharedSecretAlgorithm()) {
            case EC_P384 -> {
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
                sharedSecretResponseEcdhe.setEcServerPublicKey(sharedSecretResponse.getEcdhe());
                activationSharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((SharedSecretClientContextEcdhe) clientContext, sharedSecretResponseEcdhe);
            }
            case EC_P384_ML_L3 -> {
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
                sharedSecretResponseHybrid.setEcServerPublicKey(sharedSecretResponse.getEcdhe());
                sharedSecretResponseHybrid.setPqcCiphertext(sharedSecretResponse.getMlkem());
                activationSharedSecret = SHARED_SECRET_HYBRID.computeSharedSecret((SharedSecretClientContextHybrid) clientContext, sharedSecretResponseHybrid);
            }
            default -> throw new IllegalStateException("Unsupported shared secret algorithm: " + model.getSharedSecretAlgorithm());
        }

        // Derive keys
        final SecretKey tempKeyActSign = KeyFactory.deriveKeyMacGetActTempKey(activationSharedSecret);
        final SecretKey keyStatusMac = KeyFactory.deriveKeyMacStatus(activationSharedSecret);
        final SecretKey sharedInfo2Key = KeyFactory.deriveKeyE2eeSharedInfo2(activationSharedSecret);
        final SecretKey authenticationCodePossessionSecretKey = KeyFactory.deriveKeyAuthenticationCodePossession(activationSharedSecret);
        final SecretKey authenticationCodeKnowledgeSecretKey = KeyFactory.deriveKeyAuthenticationCodeKnowledge(activationSharedSecret);
        final SecretKey authenticationCodeBiometrySecretKey = KeyFactory.deriveKeyAuthenticationCodeBiometry(activationSharedSecret);

        final char[] password;
        if (model.getPassword() == null) {
            final Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPassword().toCharArray();
        }

        // Encrypt knowledge factor key
        final byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] encryptedKnowledgeSecretKey = EncryptedStorageUtil.storeKnowledgeFactorKey(password, authenticationCodeKnowledgeSecretKey, salt, KEY_GENERATOR);

        resultStatusObject.setVersion((long) model.getVersion().getMajorVersion());
        resultStatusObject.setActivationId(activationId);
        resultStatusObject.setCounter(0L);
        resultStatusObject.setCtrData(ctrDataBase64);
        resultStatusObject.setTemporaryKeyActSignRequestKeyObject(tempKeyActSign);
        resultStatusObject.setStatusBlobMacKeyObject(keyStatusMac);
        resultStatusObject.setSharedInfo2KeyObject(sharedInfo2Key);
        resultStatusObject.setEcServerPublicKey(serverPublicKeys.getEcdsa());
        resultStatusObject.setPqcServerPublicKey(serverPublicKeys.getMldsa());
        // TODO - store encrypted crypto 4 private keys using updated vault mechanism
        resultStatusObject.setBiometryFactorKeyObject(authenticationCodeBiometrySecretKey);
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(encryptedKnowledgeSecretKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(salt);
        resultStatusObject.setPossessionFactorKeyObject(authenticationCodePossessionSecretKey);
        resultStatusObject.setSharedSecretAlgorithm(securityContext.getSharedSecretAlgorithm().toString());
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
        fetchTemporaryKey(stepContext, EncryptorScope.APPLICATION_SCOPE, sharedSecretAlgorithm);

        final KeyPair deviceKeyPair;
        final ActivationSecurityContext securityContext;
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptorL1;
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptorL2;
        final byte[] devicePublicKeyBytes;
        final Object requestL2Object;
        switch (model.getVersion().getMajorVersion()) {
            case 3 -> {
                deviceKeyPair = ACTIVATION.generateDeviceKeyPair();
                final String temporaryPublicKey = (String) stepContext.getAttributes().get(TEMPORARY_PUBLIC_KEY);
                final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                        model.getMasterPublicKeyP256() :
                        KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(temporaryPublicKey));
                encryptorL1 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.APPLICATION_SCOPE_GENERIC,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                        new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret())
                );
                encryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.ACTIVATION_LAYER_2,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                        new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret())
                );
                securityContext = ActivationSecurityContext.builder()
                        .encryptorL1(encryptorL1)
                        .encryptorL2(encryptorL2)
                        .ecDeviceKeyPair(deviceKeyPair)
                        .sharedSecretAlgorithm(sharedSecretAlgorithm)
                        .build();
                devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, securityContext.getEcDeviceKeyPair().getPublic());
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
                final SecretKey sharedSecret = (SecretKey) stepContext.getAttributes().get(TEMPORARY_SHARED_SECRET);
                encryptorL1 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.APPLICATION_SCOPE_GENERIC,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                        new AeadSecrets(sharedSecret.getEncoded(), model.getApplicationSecret())
                );
                encryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                        EncryptorId.ACTIVATION_LAYER_2,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID)),
                        new AeadSecrets(sharedSecret.getEncoded(), model.getApplicationSecret())
                );
                final SharedSecretClientContext clientContext;
                final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
                sharedSecretRequest.setAlgorithm(model.getSharedSecretAlgorithm().toString());
                final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
                final KeyPair ecDeviceKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
                final KeyPair pqcDeviceKeyPair;
                switch (model.getSharedSecretAlgorithm()) {
                    case EC_P384 -> {
                        final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                        final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                        devicePublicKeys.setEcdsa(ecPublicKeyBase64);
                        pqcDeviceKeyPair = null;
                        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
                        clientContext = requestCryptogram.getSharedSecretClientContext();
                        sharedSecretRequest.setEcdhe(((SharedSecretRequestEcdhe)requestCryptogram.getSharedSecretRequest()).getEcClientPublicKey());
                    }
                    case EC_P384_ML_L3 -> {
                        final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                        final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                        devicePublicKeys.setEcdsa(ecPublicKeyBase64);

                        pqcDeviceKeyPair= PQC_DSA.generateKeyPair();
                        final byte[] pqcPublicKeyBytes = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcDeviceKeyPair.getPublic());
                        final String pqcPublicKeyBase64 = Base64.getEncoder().encodeToString(pqcPublicKeyBytes);
                        devicePublicKeys.setMldsa(pqcPublicKeyBase64);

                        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
                        clientContext = requestCryptogram.getSharedSecretClientContext();
                        sharedSecretRequest.setEcdhe(((SharedSecretRequestHybrid)requestCryptogram.getSharedSecretRequest()).getEcClientPublicKey());
                        sharedSecretRequest.setMlkem(((SharedSecretRequestHybrid)requestCryptogram.getSharedSecretRequest()).getPqcEncapsulationKey());
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
