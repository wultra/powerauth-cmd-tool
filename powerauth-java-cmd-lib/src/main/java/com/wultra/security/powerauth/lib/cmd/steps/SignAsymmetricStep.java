/*
 * Copyright 2025 Wultra s.r.o.
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
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
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
import com.wultra.security.powerauth.lib.cmd.steps.model.SignAsymmetricStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
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
 * Step for unlocking the device private keys using vault unlock and signing data using asymmetric algorithms.
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
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("signAsymmetricStep")
public class SignAsymmetricStep extends AbstractBaseStep<SignAsymmetricStepModel, EncryptedResponse> {

    private static final String REASON_VAULT_UNLOCK = "SIGN_WITH_DEVICE_PRIVATE_KEY";
    private static final String KEY_IDENTIFIER_KEK_DEVICE_PRIVATE = "KEK_DEVICE_PRIVATE";

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PqcDsa PQC_DSA = new MlDsa();

    private static final com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault VAULT_V3 = new com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault();
    private static final com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault VAULT_V4 = new com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault();

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public SignAsymmetricStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.SIGN_ASYMMETRIC, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public SignAsymmetricStep() {
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
    public StepContext<SignAsymmetricStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final SignAsymmetricStepModel model = new SignAsymmetricStepModel();
        model.fromMap(context);

        final int majorVersion = model.getVersion().getMajorVersion();
        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/vault/unlock")
                .uri(model.getUriString() + "/pa/v" + majorVersion + "/vault/unlock")
                .build();

        final StepContext<SignAsymmetricStepModel, EncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Prepare vault unlock request payload
        final byte[] requestBytesPayload = switch (majorVersion) {
            case 3 -> {
                final com.wultra.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload requestPayload = new com.wultra.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload();
                requestPayload.setReason(REASON_VAULT_UNLOCK);
                yield RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);
            }
            case 4 -> {
                final com.wultra.security.powerauth.rest.api.model.request.v4.VaultUnlockRequestPayload requestPayload = new com.wultra.security.powerauth.rest.api.model.request.v4.VaultUnlockRequestPayload();
                requestPayload.setKeyIdentifier(KEY_IDENTIFIER_KEK_DEVICE_PRIVATE);
                requestPayload.setReason(REASON_VAULT_UNLOCK);
                yield RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        };

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.VAULT_UNLOCK, requestBytesPayload, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<SignAsymmetricStepModel, EncryptedResponse> stepContext) throws Exception {
        final int majorVersion = stepContext.getModel().getVersion().getMajorVersion();

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = stepContext.getModel().getData();
        if (requestDataBytes == null) {
            stepContext.getStepLogger().writeError(getStep().id() + "-read-data-failed", "Reading request data failed", "Could not read request data for signing");
            stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
            return;
        }

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-request-encrypt",
                "Preparing Request Data",
                "Following data will be encrypted",
                "OK",
                requestDataBytes
        );

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

                if (!transportKeyDeduced.equals(transportMasterKey)) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-vault-unlock-failed",
                            "Vault Unlock Failed",
                            "The transportMasterKey is invalid");
                    stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
                    return;
                }

                final byte[] signature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, requestDataBytes, devicePrivateKey);

                objectMap.put("activationId", resultStatusObject.getActivationId());
                objectMap.put("signature", Base64.getEncoder().encodeToString(signature));
            }
            case 4 -> {
                final com.wultra.security.powerauth.rest.api.model.response.v4.VaultUnlockResponsePayload responsePayload = decryptResponse(stepContext, com.wultra.security.powerauth.rest.api.model.response.v4.VaultUnlockResponsePayload.class);
                final ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();
                objectMap.put("activationId", resultStatusObject.getActivationId());

                // Decrypt and show device private keys in case key identifier is KEK_DEVICE_PRIVATE
                final byte[] vaultUnlockKekDevicePrivateBytes = Base64.getDecoder().decode(responsePayload.getVaultEncryptionKey());
                final SecretKey vaultUnlockKekDevicePrivate = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(vaultUnlockKekDevicePrivateBytes);
                final byte[] encryptedEcDevicePrivateKeyBytes = Base64.getDecoder().decode(resultStatusObject.getEncryptedEcDevicePrivateKey());
                final PrivateKey ecDevicePrivateKey = VAULT_V4.decryptEcDevicePrivateKey(encryptedEcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
                final byte[] signatureEc = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, requestDataBytes, ecDevicePrivateKey);
                objectMap.put("signatureEc", Base64.getEncoder().encodeToString(signatureEc));

                if (resultStatusObject.getEncryptedPqcDevicePrivateKey() != null) {
                    final byte[] encryptedPqcDevicePrivateKeyBytes = Base64.getDecoder().decode(resultStatusObject.getEncryptedPqcDevicePrivateKey());
                    final PrivateKey pqcDevicePrivateKey = VAULT_V4.decryptPqcDevicePrivateKey(encryptedPqcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
                    final byte[] signaturePqc = PQC_DSA.sign(pqcDevicePrivateKey, requestDataBytes);
                    objectMap.put("signaturePqc", Base64.getEncoder().encodeToString(signaturePqc));
                }

            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        }

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-",
                "Sign Asymmetric Succeeded",
                "Secure vault was successfully unlocked and request data was signed successfully",
                "OK",
                objectMap
        );
    }

}
