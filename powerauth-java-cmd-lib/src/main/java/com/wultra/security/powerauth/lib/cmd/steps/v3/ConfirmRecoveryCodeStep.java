/*
 * PowerAuth Command-line utility
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
package com.wultra.security.powerauth.lib.cmd.steps.v3;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmRecoveryCodeStepModel;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.rest.api.model.request.ConfirmRecoveryRequestPayload;
import com.wultra.security.powerauth.rest.api.model.response.ConfirmRecoveryResponsePayload;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with confirm recovery logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 *      <li>3.2</li>
 *      <li>3.3</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ConfirmRecoveryCodeStep extends AbstractBaseStep<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public ConfirmRecoveryCodeStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                                   ResultStatusService resultStatusService,
                                   StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.RECOVERY_CONFIRM, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public ConfirmRecoveryCodeStep() {
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
    public StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        ConfirmRecoveryCodeStepModel model = new ConfirmRecoveryCodeStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/recovery/confirm")
                .uri(model.getUriString() + "/pa/v3/recovery/confirm")
                .build();

        StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Prepare request
        final ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(model.getRecoveryCode());

        // Encrypt the request
        final byte[] requestBytesPayload = RestClientConfiguration.defaultMapper().writeValueAsBytes(confirmRequestPayload);

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.CONFIRM_RECOVERY_CODE, requestBytesPayload, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        final ConfirmRecoveryResponsePayload confirmResponsePayload = decryptResponse(stepContext, ConfirmRecoveryResponsePayload.class);
        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("alreadyConfirmed", confirmResponsePayload.isAlreadyConfirmed());

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-confirmation-done",
                "Recovery Code Confirmed",
                "Recovery code was successfully confirmed",
                "OK",
                objectMap

        );
    }

}
