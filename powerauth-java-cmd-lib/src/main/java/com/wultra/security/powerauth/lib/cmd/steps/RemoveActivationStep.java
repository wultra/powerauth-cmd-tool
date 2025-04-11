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

import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.RemoveStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with activation remove logic.
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
@Component("removeActivationStep")
public class RemoveActivationStep extends AbstractBaseStep<RemoveStepModel, ObjectResponse<ActivationRemoveResponse>> {

    private static final ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<>() {};

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public RemoveActivationStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                                ResultStatusService resultStatusService,
                                StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ACTIVATION_REMOVE, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public RemoveActivationStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>> getResponseTypeReference(PowerAuthVersion version) {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<RemoveStepModel, ObjectResponse<ActivationRemoveResponse>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final RemoveStepModel model = new RemoveStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/activation/remove")
                .uri(model.getUriString() + "/pa/v3/activation/remove")
                .build();

        final StepContext<RemoveStepModel, ObjectResponse<ActivationRemoveResponse>> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<RemoveStepModel, ObjectResponse<ActivationRemoveResponse>> stepContext) {
        final String activationId = stepContext.getModel().getResultStatus().getActivationId();
        final Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", activationId);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-removal-done",
                "Activation Removed",
                "Activation was successfully removed from the server",
                "OK",
                objectMap

        );
    }

}
