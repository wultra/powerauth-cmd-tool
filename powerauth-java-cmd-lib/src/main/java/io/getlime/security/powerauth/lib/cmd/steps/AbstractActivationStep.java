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
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.ActivationData;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.SecurityUtil;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
     * @param stepLogger          Step logger
     */
    public AbstractActivationStep(PowerAuthStep step,
                                  List<PowerAuthVersion> supportedVersions,
                                  ResultStatusService resultStatusService,
                                  StepLogger stepLogger) {
        super(step, supportedVersions, resultStatusService, stepLogger);
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

        ResultStatusObject resultStatusObject = processResponse(encryptedResponseL1, stepContext);
        model.setResultStatusObject(resultStatusObject);

        resultStatusService.save(model);

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("activationStatusFile", model.getStatusFileName());
        objectMap.put("activationStatusFileContent", model.getResultStatusObject());
        objectMap.put("deviceKeyFingerprint", ACTIVATION.computeActivationFingerprint(stepContext.getDeviceKeyPair().getPublic(), resultStatusObject.getServerPublicKeyObject(), resultStatusObject.getActivationId()));
        stepLogger.writeItem(
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

        // Read activation layer 1 response and decrypt it
        byte[] macL1 = BaseEncoding.base64().decode(encryptedResponseL1.getMac());
        byte[] encryptedDataL1 = BaseEncoding.base64().decode(encryptedResponseL1.getEncryptedData());
        EciesCryptogram responseCryptogramL1 = new EciesCryptogram(macL1, encryptedDataL1);
        byte[] decryptedDataL1 = context.getEciesEncryptorL1().decryptResponse(responseCryptogramL1);

        // Read activation layer 1 response from data
        ActivationLayer1Response responseL1 = MAPPER.readValue(decryptedDataL1, ActivationLayer1Response.class);

        stepLogger.writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Layer 1 Response",
                "Following layer 1 activation data were decrypted",
                "OK",
                responseL1
        );

        // Decrypt layer 2 response
        byte[] macL2 = BaseEncoding.base64().decode(responseL1.getActivationData().getMac());
        byte[] encryptedDataL2 = BaseEncoding.base64().decode(responseL1.getActivationData().getEncryptedData());
        EciesCryptogram responseCryptogramL2 = new EciesCryptogram(macL2, encryptedDataL2);
        byte[] decryptedDataL2 = context.getEciesEncryptorL2().decryptResponse(responseCryptogramL2);

        // Convert activation layer 2 response from JSON to object and extract activation parameters
        ActivationLayer2Response responseL2 = MAPPER.readValue(decryptedDataL2, ActivationLayer2Response.class);

        stepLogger.writeItem(
                getStep().id() + "-response-decrypt-inner",
                "Decrypted Layer 2 Response",
                "Following layer 2 activation data were decrypted",
                "OK",
                responseL2
        );

        String activationId = responseL2.getActivationId();
        String ctrDataBase64 = responseL2.getCtrData();
        String serverPublicKeyBase64 = responseL2.getServerPublicKey();
        PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));

        // Compute master secret key
        SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(context.getDeviceKeyPair().getPrivate(), serverPublicKey);

        // Derive PowerAuth keys from master secret key
        SecretKey signaturePossessionSecretKey = KEY_FACTORY.generateClientSignaturePossessionKey(masterSecretKey);
        SecretKey signatureKnowledgeSecretKey = KEY_FACTORY.generateClientSignatureKnowledgeKey(masterSecretKey);
        SecretKey signatureBiometrySecretKey = KEY_FACTORY.generateClientSignatureBiometryKey(masterSecretKey);
        SecretKey transportMasterKey = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
        // DO NOT EVER STORE ...
        SecretKey vaultUnlockMasterKey = KEY_FACTORY.generateServerEncryptedVaultKey(masterSecretKey);

        // Encrypt the original device private key using the vault unlock key
        byte[] encryptedDevicePrivateKey = VAULT.encryptDevicePrivateKey(context.getDeviceKeyPair().getPrivate(), vaultUnlockMasterKey);

        char[] password;
        if (model.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Select a password to encrypt the knowledge related key: ");
        } else {
            password = model.getPassword().toCharArray();
        }

        byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        byte[] cSignatureKnowledgeSecretKey = EncryptedStorageUtil.storeSignatureKnowledgeKey(password, signatureKnowledgeSecretKey, salt, KEY_GENERATOR);

        ResultStatusObject resultStatusObject = model.getResultStatusObject();

        resultStatusObject.setActivationId(activationId);
        resultStatusObject.getCounter().set(0L);
        resultStatusObject.setCtrDataBase(ctrDataBase64);
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

        // Get activation key and secret
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

        EciesEncryptor eciesEncryptorL1 = ECIES_FACTORY.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
        EciesEncryptor eciesEncryptorL2 = ECIES_FACTORY.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(), applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2);

        KeyPair deviceKeyPair = ACTIVATION.generateDeviceKeyPair();

        stepContext.setEciesEncryptorL1(eciesEncryptorL1);
        stepContext.setEciesEncryptorL2(eciesEncryptorL2);
        stepContext.setDeviceKeyPair(deviceKeyPair);

        // Read the identity attributes and custom attributes
        Map<String, String> identityAttributes = model.getIdentityAttributes();
        if (identityAttributes != null && !identityAttributes.isEmpty()) {
            stepLogger.writeItem(
                    getStep().id() + "-identity-attributes",
                    "Identity Attributes",
                    "Following attributes are used to authenticate user",
                    "OK",
                    identityAttributes
            );
        }

        Map<String, Object> customAttributes = model.getCustomAttributes();
        if (customAttributes != null && !customAttributes.isEmpty()) {
            stepLogger.writeItem(
                    getStep().id() + "-custom-attributes",
                    "Custom Attributes",
                    "Following attributes are used as custom attributes for the request",
                    "OK",
                    customAttributes
            );
        }

        // Generate device key pair
        byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(stepContext.getDeviceKeyPair().getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);

        // Create activation layer 2 request which is decryptable only on PowerAuth server
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(model.getActivationName());
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        requestL2.setPlatform(model.getPlatform());
        requestL2.setDeviceInfo(model.getDeviceInfo());

        final boolean useIv = model.getVersion().useIv();

        // Encrypt request data using ECIES in application scope with sharedInfo1 = /pa/activation
        EciesCryptogram eciesCryptogramL2 = SecurityUtil.encryptObject(stepContext.getEciesEncryptorL2(), requestL2, useIv);

        // Prepare the encrypted layer 2 request
        EciesEncryptedRequest encryptedRequestL2 = SecurityUtil.createEncryptedRequest(eciesCryptogramL2, useIv);

        // Prepare activation layer 1 request which is decryptable on intermediate server
        ActivationLayer1Request requestL1 = prepareLayer1Request(stepContext, encryptedRequestL2);

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Building activation request object",
                "Following activation attributes will be encrypted and sent to the server",
                "OK",
                requestL1
        );

        // Encrypt the layer 1 request using ECIES in application scope with sharedInfo1 = /pa/generic/application
        EciesCryptogram eciesCryptogramL1 = SecurityUtil.encryptObject(stepContext.getEciesEncryptorL1(), requestL1, useIv);

        // Prepare the encrypted layer 1 request
        EciesEncryptedRequest encryptedRequestL1 = SecurityUtil.createEncryptedRequest(eciesCryptogramL1, useIv);

        stepContext.getRequestContext().setRequestObject(encryptedRequestL1);
    }

}
