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

import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helper class with vault unlock logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 *      <li>3.2</li>
 *      <li>3.3</li>
 *      <li>4.0</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("vaultUnlockStep")
public class VaultUnlockStep extends AbstractBaseStep<VaultUnlockStepModel, EncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC = new MlDsaKeyConvertor();

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault VAULT_V3 = new com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault();
    private static final com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault VAULT_V4 = new com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault();

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public VaultUnlockStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.VAULT_UNLOCK, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public VaultUnlockStep() {
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
    public StepContext<VaultUnlockStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final VaultUnlockStepModel model = new VaultUnlockStepModel();
        model.fromMap(context);

        final int majorVersion = model.getVersion().getMajorVersion();
        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/vault/unlock")
                .uri(model.getUriString() + "/pa/v" + majorVersion + "/vault/unlock")
                .build();

        final StepContext<VaultUnlockStepModel, EncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Prepare vault unlock request payload
        final byte[] requestBytesPayload = switch (majorVersion) {
            case 3 -> {
                final com.wultra.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload requestPayload = new com.wultra.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload();
                requestPayload.setReason(model.getReason());
                yield RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);
            }
            case 4 -> {
                if (model.getKeyIdentifier() == null) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-vault-unlock-failed",
                            "Vault Unlock Failed",
                            "Key identifier is not specified");
                    stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
                    yield null;
                }
                if (!model.getKeyIdentifier().equals("KEK_DEVICE_PRIVATE")
                        && !model.getKeyIdentifier().equals("KDK_APP_VAULT_KNOWLEDGE")
                        && !model.getKeyIdentifier().equals("KDK_APP_VAULT_2FA")) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-vault-unlock-failed",
                            "Vault Unlock Failed",
                            "Key identifier is not valid");
                    stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
                    yield null;
                }
                final com.wultra.security.powerauth.rest.api.model.request.v4.VaultUnlockRequestPayload requestPayload = new com.wultra.security.powerauth.rest.api.model.request.v4.VaultUnlockRequestPayload();
                requestPayload.setKeyIdentifier(model.getKeyIdentifier());
                requestPayload.setReason(model.getReason());
                yield RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        };

        if (requestBytesPayload == null) {
            return null;
        }

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.VAULT_UNLOCK, requestBytesPayload, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<VaultUnlockStepModel, EncryptedResponse> stepContext) throws Exception {
        final int majorVersion = stepContext.getModel().getVersion().getMajorVersion();

        final Map<String, Object> objectMap = new LinkedHashMap<>();
        switch (majorVersion) {
            case 3 -> {
                final com.wultra.security.powerauth.rest.api.model.response.v3.VaultUnlockResponsePayload responsePayload = decryptResponse(stepContext, com.wultra.security.powerauth.rest.api.model.response.v3.VaultUnlockResponsePayload.class);
                final ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();

                final SecretKey transportMasterKey = resultStatusObject.getTransportMasterKeyObject();
                if (transportMasterKey == null) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-vault-unlock-failed",
                            "Vault Unlock Failed",
                            "The transportMasterKey is null");
                    stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
                    return;
                }

                final byte[] encryptedDevicePrivateKeyBytes = resultStatusObject.getEncryptedEcDevicePrivateKeyBytes();
                final byte[] encryptedVaultEncryptionKey = Base64.getDecoder().decode(responsePayload.getEncryptedVaultEncryptionKey());

                final SecretKey vaultEncryptionKey = VAULT_V3.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey);
                final PrivateKey devicePrivateKey = VAULT_V3.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
                final PublicKey serverPublicKey = resultStatusObject.getEcServerPublicKeyObject();

                final SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                final SecretKey transportKeyDeduced = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
                final boolean equal = transportKeyDeduced.equals(transportMasterKey);
                objectMap.put("activationId", resultStatusObject.getActivationId());
                objectMap.put("encryptedVaultEncryptionKey", Base64.getEncoder().encodeToString(encryptedVaultEncryptionKey));
                objectMap.put("transportMasterKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(transportMasterKey)));
                objectMap.put("vaultEncryptionKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(vaultEncryptionKey)));
                objectMap.put("devicePrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(devicePrivateKey)));
                objectMap.put("privateKeyDecryptionSuccessful", (equal ? "true" : "false"));
            }
            case 4 -> {
                final com.wultra.security.powerauth.rest.api.model.response.v4.VaultUnlockResponsePayload responsePayload = decryptResponse(stepContext, com.wultra.security.powerauth.rest.api.model.response.v4.VaultUnlockResponsePayload.class);
                final ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();
                objectMap.put("activationId", resultStatusObject.getActivationId());
                objectMap.put("vaultEncryptionKey", responsePayload.getVaultEncryptionKey());

                // Decrypt and show device private keys in case key identifier is KEK_DEVICE_PRIVATE
                if ("KEK_DEVICE_PRIVATE".equals(stepContext.getModel().getKeyIdentifier())) {
                    final byte[] vaultUnlockKekDevicePrivateBytes = Base64.getDecoder().decode(responsePayload.getVaultEncryptionKey());
                    final SecretKey vaultUnlockKekDevicePrivate = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(vaultUnlockKekDevicePrivateBytes);
                    final byte[] encryptedEcDevicePrivateKeyBytes = resultStatusObject.getEncryptedEcDevicePrivateKeyBytes();
                    final PrivateKey ecDevicePrivateKey = VAULT_V4.decryptEcDevicePrivateKey(encryptedEcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
                    objectMap.put("deviceEcPrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(ecDevicePrivateKey)));
                    if (resultStatusObject.getSharedSecretAlgorithm().equals(SharedSecretAlgorithm.EC_P384_ML_L3.name())
                            || resultStatusObject.getSharedSecretAlgorithm().equals(SharedSecretAlgorithm.EC_P384_ML_L5.name())) {
                        final byte[] encryptedPqcDevicePrivateKeyBytes = resultStatusObject.getEncryptedPqcDevicePrivateKeyBytes();
                        final PrivateKey pqcDevicePrivateKey = VAULT_V4.decryptPqcDevicePrivateKey(encryptedPqcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
                        objectMap.put("devicePqcPrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR_PQC.convertPrivateKeyToBytes(pqcDevicePrivateKey)));
                    }
                }
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        }

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-vault-unlocked",
                "Vault Unlocked",
                "Secure vault was successfully unlocked",
                "OK",
                objectMap
        );
    }

}
