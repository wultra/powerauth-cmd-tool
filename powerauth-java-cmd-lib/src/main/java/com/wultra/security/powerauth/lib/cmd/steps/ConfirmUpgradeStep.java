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

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmUpgradeStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Step for confirming upgrade of PowerAuth protocol.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>4.0</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("confirmUpgradeStep")
public class ConfirmUpgradeStep extends AbstractBaseStep<ConfirmUpgradeStepModel, Response> {

    private static final ParameterizedTypeReference<Response> RESPONSE_TYPE_REFERENCE = new ParameterizedTypeReference<>() {};

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public ConfirmUpgradeStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.UPGRADE_CONFIRM, PowerAuthVersion.VERSION_4, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public ConfirmUpgradeStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<Response> getResponseTypeReference(PowerAuthVersion version) {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<ConfirmUpgradeStepModel, Response> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final ConfirmUpgradeStepModel model = new ConfirmUpgradeStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/upgrade/confirm")
                .uri(model.getUriString() + "/pa/v4/upgrade/confirm")
                .build();

        final StepContext<ConfirmUpgradeStepModel, Response> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        requestContext.setRequestObject(PowerAuthConst.EMPTY_JSON_BYTES);
        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<ConfirmUpgradeStepModel, Response> stepContext) throws Exception {
        final ConfirmUpgradeStepModel model = stepContext.getModel();
        incrementCounter(model);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-upgrade-done",
                "Upgrade confirmation successfully completed",
                "Upgrade confirmation was successfully completed",
                "OK",
                null

        );
    }

}
