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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.rest.api.model.request.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponsePayload;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with vault unlock logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "vaultUnlockStepV3")
public class VaultUnlockStep extends AbstractBaseStep<VaultUnlockStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

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
        super(PowerAuthStep.VAULT_UNLOCK, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

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
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<VaultUnlockStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        VaultUnlockStepModel model = new VaultUnlockStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/vault/unlock")
                .uri(model.getUriString() + "/pa/v3/vault/unlock")
                .build();

        StepContext<VaultUnlockStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Prepare vault unlock request payload
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason(model.getReason());

        final byte[] requestBytesPayload = RestClientConfiguration.defaultMapper().writeValueAsBytes(requestPayload);

        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.VAULT_UNLOCK, requestBytesPayload);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<VaultUnlockStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        final VaultUnlockResponsePayload responsePayload = decryptResponse(stepContext, VaultUnlockResponsePayload.class);

        ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();

        SecretKey transportMasterKey = resultStatusObject.getTransportMasterKeyObject();
        byte[] encryptedDevicePrivateKeyBytes = resultStatusObject.getEncryptedDevicePrivateKeyBytes();

        byte[] encryptedVaultEncryptionKey = Base64.getDecoder().decode(responsePayload.getEncryptedVaultEncryptionKey());

        PowerAuthClientVault vault = new PowerAuthClientVault();
        SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey);
        PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
        PublicKey serverPublicKey = resultStatusObject.getServerPublicKeyObject();

        SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
        SecretKey transportKeyDeduced = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
        boolean equal = transportKeyDeduced.equals(transportMasterKey);

        // Print the results
        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("encryptedVaultEncryptionKey", Base64.getEncoder().encodeToString(encryptedVaultEncryptionKey));
        objectMap.put("transportMasterKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKey)));
        objectMap.put("vaultEncryptionKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertSharedSecretKeyToBytes(vaultEncryptionKey)));
        objectMap.put("devicePrivateKey", Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPrivateKeyToBytes(devicePrivateKey)));
        objectMap.put("privateKeyDecryptionSuccessful", (equal ? "true" : "false"));

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-vault-unlocked",
                "Vault Unlocked",
                "Secure vault was successfully unlocked",
                "OK",
                objectMap
        );
    }

}
