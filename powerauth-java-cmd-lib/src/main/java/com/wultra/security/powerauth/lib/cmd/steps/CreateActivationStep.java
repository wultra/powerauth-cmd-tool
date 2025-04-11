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
package com.wultra.security.powerauth.lib.cmd.steps;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractActivationStep;
import com.wultra.security.powerauth.rest.api.model.entity.ActivationType;
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
 *     <li>3.2</li>
 *     <li>3.3</li>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("createActivationStep")
public class CreateActivationStep extends AbstractActivationStep<CreateActivationStepModel> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public CreateActivationStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ACTIVATION_CREATE_CUSTOM, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public CreateActivationStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public StepContext<CreateActivationStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final CreateActivationStepModel model = new CreateActivationStepModel();
        model.fromMap(context);

        final int majorVersion = model.getVersion().getMajorVersion();
        final RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v" + majorVersion + "/activation/create")
                .build();

        final StepContext<CreateActivationStepModel, EncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        addEncryptedRequest(stepContext);
        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        return stepContext;
    }

    @Override
    protected Object prepareLayer1Request(
            StepContext<CreateActivationStepModel, EncryptedResponse> stepContext,
            EncryptedRequest encryptedRequestL2) {
        return switch (stepContext.getModel().getVersion().getMajorVersion()) {
            case 3: {
                final com.wultra.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request requestL1 = new com.wultra.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request();
                requestL1.setType(ActivationType.DIRECT);
                requestL1.setActivationData((EciesEncryptedRequest) encryptedRequestL2);
                requestL1.setIdentityAttributes(stepContext.getModel().getIdentityAttributes());
                requestL1.setCustomAttributes(stepContext.getModel().getCustomAttributes());
                yield requestL1;
            }
            case 4: {
                final com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer1Request requestL1 = new com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer1Request();
                requestL1.setType(ActivationType.DIRECT);
                requestL1.setActivationData((AeadEncryptedRequest) encryptedRequestL2);
                requestL1.setIdentityAttributes(stepContext.getModel().getIdentityAttributes());
                requestL1.setCustomAttributes(stepContext.getModel().getCustomAttributes());
                yield requestL1;
            }
            default:
                throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        };
    }
}
