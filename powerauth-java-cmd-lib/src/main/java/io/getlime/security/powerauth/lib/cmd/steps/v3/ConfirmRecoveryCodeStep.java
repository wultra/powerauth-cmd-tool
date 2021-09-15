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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.ConfirmRecoveryCodeStepModel;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.rest.api.model.request.v3.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
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
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ConfirmRecoveryCodeStep extends AbstractBaseStep<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public ConfirmRecoveryCodeStep(PowerAuthHeaderService powerAuthHeaderService,
                                   ResultStatusService resultStatusService,
                                   StepLogger stepLogger) {
        super(PowerAuthStep.RECOVERY_CONFIRM, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    /**
     * Constructor for backward compatibility
     */
    public ConfirmRecoveryCodeStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_SERVICE,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER
        );
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> prepareStepContext(Map<String, Object> context) throws Exception {
        ConfirmRecoveryCodeStepModel model = new ConfirmRecoveryCodeStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/recovery/confirm")
                .uri(model.getUriString() + "/pa/v3/recovery/confirm")
                .build();

        StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(model, requestContext);

        // Prepare request
        final ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(model.getRecoveryCode());

        // Encrypt the request
        final byte[] requestBytesPayload = RestClientConfiguration.defaultMapper().writeValueAsBytes(confirmRequestPayload);

        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.CONFIRM_RECOVERY_CODE, requestBytesPayload);

        powerAuthHeaderService.addSignatureHeader(stepContext, false);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<ConfirmRecoveryCodeStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        EciesEncryptor encryptor = stepContext.getEncryptor();
        EciesEncryptedResponse response = stepContext.getResponseContext().getResponseBodyObject();
        final ConfirmRecoveryResponsePayload confirmResponsePayload =
                decryptResponse(encryptor, response, ConfirmRecoveryResponsePayload.class);

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("alreadyConfirmed", confirmResponsePayload.getAlreadyConfirmed());

        stepLogger.writeItem(
                getStep().id() + "-confirmation-done",
                "Recovery Code Confirmed",
                "Recovery code was successfully confirmed",
                "OK",
                objectMap

        );
    }

}
