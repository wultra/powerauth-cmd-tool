/*
 * Copyright 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Class with create activation logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "createActivationStepV3")
public class CreateActivationStep extends AbstractActivationStep<CreateActivationStepModel> {

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public CreateActivationStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_CREATE_CUSTOM, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    @Override
    public StepContext<CreateActivationStepModel, EciesEncryptedResponse> prepareStepContext(Map<String, Object> context) throws Exception {
        CreateActivationStepModel model = new CreateActivationStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v3/activation/create")
                .build();

        StepContext<CreateActivationStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(model, requestContext);

        powerAuthHeaderService.addEncryptionHeader(requestContext, model);
        addEncryptedRequest(stepContext);

        return stepContext;
    }

    @Override
    protected ActivationLayer1Request prepareLayer1Request(StepContext<CreateActivationStepModel, EciesEncryptedResponse> stepContext, EciesEncryptedRequest encryptedRequestL2) {
        ActivationLayer1Request requestL1 = new ActivationLayer1Request();
        requestL1.setType(ActivationType.CUSTOM);
        requestL1.setActivationData(encryptedRequestL2);
        requestL1.setIdentityAttributes(stepContext.getModel().getIdentityAttributes());
        requestL1.setCustomAttributes(stepContext.getModel().getCustomAttributes());
        return requestL1;
    }

}
