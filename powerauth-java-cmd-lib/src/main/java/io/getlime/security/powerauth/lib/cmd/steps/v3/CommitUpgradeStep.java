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

import io.getlime.core.rest.model.base.response.Response;
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
import io.getlime.security.powerauth.lib.cmd.steps.model.CommitUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Step for committing upgrade to PowerAuth protocol version 3.0.
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
public class CommitUpgradeStep extends AbstractBaseStep<CommitUpgradeStepModel, Response> {

    public static final ParameterizedTypeReference<Response> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<Response>() { };

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public CommitUpgradeStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLogger stepLogger) {
        super(PowerAuthStep.UPGRADE_COMMIT, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    /**
     * Constructor for backward compatibility
     */
    public CommitUpgradeStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_SERVICE,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER
        );
    }

    @Override
    protected ParameterizedTypeReference<Response> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<CommitUpgradeStepModel, Response> prepareStepContext(Map<String, Object> context) throws Exception {
        CommitUpgradeStepModel model = new CommitUpgradeStepModel();
        model.fromMap(context);

        ResultStatusObject resultStatusObject = model.getResultStatus();

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/upgrade/commit")
                .uri(model.getUriString() + "/pa/v3/upgrade/commit")
                .build();

        StepContext<CommitUpgradeStepModel, Response> stepContext =
                buildStepContext(model, requestContext);

        // Make sure hash based counter is used for calculating the signature, in case of an error the version change is not saved
        resultStatusObject.setVersion(3L);

        requestContext.setRequestObject(PowerAuthConst.EMPTY_JSON_BYTES);
        powerAuthHeaderService.addSignatureHeader(stepContext, false);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<CommitUpgradeStepModel, Response> stepContext) throws Exception {
        CommitUpgradeStepModel model = stepContext.getModel();

        incrementCounter(model);

        stepLogger.writeItem(
                getStep().id() + "-upgrade-done",
                "Upgrade commit successfully completed",
                "Upgrade commit was successfully completed",
                "OK",
                null

        );
    }

}
