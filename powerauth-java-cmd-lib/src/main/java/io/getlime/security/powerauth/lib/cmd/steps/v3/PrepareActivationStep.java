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

import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class with prepare activation logic.
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
@Component(value = "prepareActivationStepV3")
public class PrepareActivationStep extends AbstractActivationStep<PrepareActivationStepModel> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public PrepareActivationStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ACTIVATION_CREATE, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public PrepareActivationStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public StepContext<PrepareActivationStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.fromMap(context);

        // Fetch and parse the activation code
        Pattern p = Pattern.compile("^[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}$");
        Matcher m = p.matcher(model.getActivationCode());
        if (!m.find()) {
            stepLogger.writeError("activation-create-activation-code", "Prepare activation step failed", "Activation code has invalid format");
            stepLogger.writeDoneFailed("activation-create-error-activation-code");
            return null;
        }
        final String activationCode = model.getActivationCode();

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationCode", activationCode);
        stepLogger.writeItem(
                getStep().id() + "-activation-code",
                "Activation code",
                "Storing activation code",
                "OK",
                objectMap
        );

        RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v3/activation/create")
                .build();

        StepContext<PrepareActivationStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);
        addEncryptedRequest(stepContext, model.getVersion());

        return stepContext;
    }

    @Override
    protected ActivationLayer1Request prepareLayer1Request(
            StepContext<PrepareActivationStepModel, EciesEncryptedResponse> stepContext,
            EciesEncryptedRequest encryptedRequestL2) {
        ActivationLayer1Request requestL1 = new ActivationLayer1Request();
        requestL1.setType(ActivationType.CODE);
        requestL1.setActivationData(encryptedRequestL2);
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("code", stepContext.getModel().getActivationCode());
        requestL1.setIdentityAttributes(identityAttributes);
        return requestL1;
    }

}
