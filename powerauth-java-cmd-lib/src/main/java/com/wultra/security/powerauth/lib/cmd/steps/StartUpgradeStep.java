/*
 * Copyright 2018 Wultra s.r.o.
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

import com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
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
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.UpgradeSecurityContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.rest.api.model.request.v4.DevicePublicKeys;
import com.wultra.security.powerauth.rest.api.model.request.v4.SharedSecretRequest;
import com.wultra.security.powerauth.rest.api.model.request.v4.UpgradeRequestPayload;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerPublicKeys;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import com.wultra.security.powerauth.rest.api.model.response.v4.UpgradeResponsePayload;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

/**
 * Step for starting upgrade to PowerAuth protocol version 4.0.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class StartUpgradeStep extends AbstractBaseStep<StartUpgradeStepModel, EncryptedResponse> {

    private static final PowerAuthClientActivation CLIENT_ACTIVATION_V4 = new PowerAuthClientActivation();
    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final PowerAuthClientKeyFactory KEY_FACTORY_V4 = new PowerAuthClientKeyFactory();
    private static final PowerAuthClientVault VAULT_V4 = new PowerAuthClientVault();

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public StartUpgradeStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                            ResultStatusService resultStatusService,
                            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.UPGRADE_START, PowerAuthVersion.VERSION_4, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public StartUpgradeStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<EncryptedResponse> getResponseTypeReference(PowerAuthVersion version) {
        return getResponseTypeReferenceEncrypted(version);
    }

    @Override
    public StepContext<StartUpgradeStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final StartUpgradeStepModel model = new StartUpgradeStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/upgrade/start")
                .uri(model.getUriString() + "/pa/v4/upgrade/start")
                .build();

        final StepContext<StartUpgradeStepModel, EncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.APPLICATION_SCOPE);
        boolean temporaryKeyFetchSucceeded = fetchTemporaryKey(stepContext, EncryptorScope.APPLICATION_SCOPE, sharedSecretAlgorithm);
        if (!temporaryKeyFetchSucceeded) {
            // Error is already logged
            return null;
        }

        final SecretKey sharedSecret = stepContext.getTemporaryKeyContext().getTemporarySharedSecret();
        if (sharedSecret == null) {
            stepContext.getStepLogger().writeError(getStep().id() + "-error-missing-temporary-shared-secret", "Temporary shared secret is missing", "Temporary shared secret was not derived when adding encrypted request");
            return null;
        }
        final String temporaryKeyId = stepContext.getTemporaryKeyContext().getTemporaryKeyId();
        // Encryption is done using protocol version 4.0 (AEAD)
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.UPGRADE_START,
                new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId),
                new AeadSecrets(sharedSecret.getEncoded(), model.getApplicationSecret())
        );
        final SharedSecretClientContext clientContext;
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(model.getSharedSecretAlgorithm().toString());
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        final KeyPair ecDeviceKeyPair = CLIENT_ACTIVATION_V4.generateDeviceEcKeyPair();
        final KeyPair pqcDeviceKeyPair;
        switch (model.getSharedSecretAlgorithm()) {
            case EC_P384 -> {
                final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                devicePublicKeys.setEcdsa(ecPublicKeyBase64);
                final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
                clientContext = requestCryptogram.getSharedSecretClientContext();
                sharedSecretRequest.setEcdhe(((SharedSecretRequestEcdhe)requestCryptogram.getSharedSecretRequest()).getEcClientPublicKey());
                pqcDeviceKeyPair = null;
            }
            case EC_P384_ML_L3 -> {
                final byte[] ecPublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
                final String ecPublicKeyBase64 = Base64.getEncoder().encodeToString(ecPublicKeyBytes);
                devicePublicKeys.setEcdsa(ecPublicKeyBase64);

                pqcDeviceKeyPair = CLIENT_ACTIVATION_V4.generateDevicePqcKeyPair();
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

        final UpgradeSecurityContext securityContext = UpgradeSecurityContext.builder()
                .encryptor(encryptor)
                .sharedSecretClientContext(clientContext)
                .devicePublicKeys(devicePublicKeys)
                .ecDeviceKeyPair(ecDeviceKeyPair)
                .pqcDeviceKeyPair(pqcDeviceKeyPair)
                .sharedSecretAlgorithm(model.getSharedSecretAlgorithm())
                .build();
        stepContext.setSecurityContext(securityContext);

        final UpgradeRequestPayload requestPayload = new UpgradeRequestPayload();
        requestPayload.setSharedSecretRequest(sharedSecretRequest);
        requestPayload.setDevicePublicKeys(devicePublicKeys);
        requestPayload.setEnableBiometry(true);

        // Encrypt the request in application scope
        final EncryptedRequest encryptedRequest = SecurityUtil.encryptObject(encryptor, requestPayload);
        stepContext.getRequestContext().setRequestObject(encryptedRequest);

        // The version has to be enforced to 3.3 for so that the authentication is calculated using the previous protocol version
        model.setVersion(PowerAuthVersion.V3_3);
        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);
        model.setVersion(PowerAuthVersion.V4_0);

        // The encryption header uses the exact version configured for the step
        final PowerAuthEncryptionHttpHeader encHeader = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), null, model.getVersion().value());
        final String encHeaderValue = encHeader.buildHttpHeader();
        requestContext.getHttpHeaders().put(PowerAuthEncryptionHttpHeader.HEADER_NAME, encHeaderValue);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<StartUpgradeStepModel, EncryptedResponse> stepContext) throws Exception {
        final StartUpgradeStepModel model = stepContext.getModel();
        final UpgradeSecurityContext securityContext = (UpgradeSecurityContext) stepContext.getSecurityContext();
        final ResultStatusObject resultStatusObject = model.getResultStatus();
        // Decrypt response
        final AeadEncryptedResponse aeadResponse = (AeadEncryptedResponse) stepContext.getResponseContext().getResponseBodyObject();
        final byte[] decryptedBytes = securityContext.getEncryptor().decryptResponse(new AeadEncryptedResponse(
                aeadResponse.getEncryptedData(),
                aeadResponse.getTimestamp()
        ));
        final UpgradeResponsePayload responsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, UpgradeResponsePayload.class);
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                responsePayload
        );
        final SharedSecretClientContext clientContext = securityContext.getSharedSecretClientContext();
        final ServerPublicKeys serverPublicKeys = responsePayload.getServerPublicKeys();
        final SharedSecretResponse sharedSecretResponse = responsePayload.getSharedSecretResponse();
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
        final SecretKey tempKeyActSign = KEY_FACTORY_V4.generateKeyMacGetActTempKey(activationSharedSecret);
        final SecretKey keyStatusMac = KEY_FACTORY_V4.generateKeyMacStatus(activationSharedSecret);
        final SecretKey sharedInfo2Key = KEY_FACTORY_V4.generateSharedInfo2Key(activationSharedSecret);
        final SecretKey authenticationCodePossessionSecretKey = KEY_FACTORY_V4.generatePossessionFactorKey(activationSharedSecret);
        final SecretKey authenticationCodeKnowledgeSecretKey = KEY_FACTORY_V4.generateKnowledgeFactorKey(activationSharedSecret);
        final SecretKey authenticationCodeBiometrySecretKey = KEY_FACTORY_V4.generateBiometryFactorKey(activationSharedSecret);
        final SecretKey vaultUnlockKekDevicePrivate = KEY_FACTORY_V4.generateKeyKekDevicePrivate(activationSharedSecret);

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

        final PublicKey ecDevicePublicKey = securityContext.getEcDeviceKeyPair().getPublic();
        final PublicKey pqcDevicePublicKey = securityContext.getPqcDeviceKeyPair() != null ? securityContext.getPqcDeviceKeyPair().getPublic() : null;

        // Encrypt device private keys
        final byte[] encryptedEcDevicePrivateKey = VAULT_V4.encryptEcDevicePrivateKey(securityContext.getEcDeviceKeyPair().getPrivate(), vaultUnlockKekDevicePrivate);
        final byte[] encryptedPqcDevicePrivateKey;
        if (securityContext.getPqcDeviceKeyPair() != null) {
            encryptedPqcDevicePrivateKey = VAULT_V4.encryptPqcDevicePrivateKey(securityContext.getPqcDeviceKeyPair().getPrivate(), vaultUnlockKekDevicePrivate);
        } else {
            encryptedPqcDevicePrivateKey = null;
        }

        // Set version to 4 after upgrade, all keys have been successfully derived
        resultStatusObject.setVersion(4L);

        // Update the counter data for V4
        resultStatusObject.setCtrData(responsePayload.getCtrData());
        resultStatusObject.setTemporaryKeyActSignRequestKeyObject(tempKeyActSign);
        resultStatusObject.setStatusBlobMacKeyObject(keyStatusMac);
        resultStatusObject.setSharedInfo2KeyObject(sharedInfo2Key);
        resultStatusObject.setEcServerPublicKey(serverPublicKeys.getEcdsa());
        if (serverPublicKeys.getMldsa() != null) {
            resultStatusObject.setPqcServerPublicKey(serverPublicKeys.getMldsa());
        }
        resultStatusObject.setEncryptedEcDevicePrivateKeyBytes(encryptedEcDevicePrivateKey);
        if (encryptedPqcDevicePrivateKey != null) {
            resultStatusObject.setEncryptedPqcDevicePrivateKeyBytes(encryptedPqcDevicePrivateKey);
        }
        resultStatusObject.setBiometryFactorKeyObject(authenticationCodeBiometrySecretKey);
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(encryptedKnowledgeSecretKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(salt);
        resultStatusObject.setPossessionFactorKeyObject(authenticationCodePossessionSecretKey);
        resultStatusObject.setSharedSecretAlgorithm(securityContext.getSharedSecretAlgorithm().toString());
        resultStatusObject.setEcDevicePublicKeyObject(ecDevicePublicKey);
        if (pqcDevicePublicKey != null) {
            resultStatusObject.setPqcDevicePublicKeyObject(pqcDevicePublicKey);
        }

        resultStatusService.save(model);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-completed",
                "Upgrade start step successfully completed",
                "Upgrade start step was successfully completed",
                "OK",
                responsePayload
        );
    }

}
