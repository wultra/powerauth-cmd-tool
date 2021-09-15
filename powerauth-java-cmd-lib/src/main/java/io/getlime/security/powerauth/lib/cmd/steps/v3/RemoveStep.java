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

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.RemoveStepModel;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
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
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "removeStepV3")
public class RemoveStep extends AbstractBaseStep<RemoveStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public RemoveStep(PowerAuthHeaderService powerAuthHeaderService,
                      ResultStatusService resultStatusService,
                      StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_REMOVE, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<RemoveStepModel, EciesEncryptedResponse> prepareStepContext(Map<String, Object> context) throws Exception {
        RemoveStepModel model = new RemoveStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/activation/remove")
                .uri(model.getUriString() + "/pa/v3/activation/remove")
                .build();

        StepContext<RemoveStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(model, requestContext);

        powerAuthHeaderService.addSignatureHeader(stepContext, false);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<RemoveStepModel, EciesEncryptedResponse> stepContext) {
        String activationId = stepContext.getModel().getResultStatusObject().getActivationId();
        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", activationId);

        stepLogger.writeItem(
                getStep().id() + "-removal-done",
                "Activation Removed",
                "Activation was successfully removed from the server",
                "OK",
                objectMap

        );
    }

}
