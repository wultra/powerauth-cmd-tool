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
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.util.VerifyAuthenticationCodeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Helper class with authentication code verification logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Petr Dvorak
 */
@Component
public class VerifyAuthenticationStep extends AbstractBaseStep<VerifyAuthenticationStepModel, ObjectResponse<Map<String, Object>>> {

    private static final ParameterizedTypeReference<ObjectResponse<Map<String, Object>>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<>() {};

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public VerifyAuthenticationStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.AUTHENTICATION_VERIFY, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public VerifyAuthenticationStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public ParameterizedTypeReference<ObjectResponse<Map<String, Object>>> getResponseTypeReference(PowerAuthVersion version) {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<VerifyAuthenticationStepModel, ObjectResponse<Map<String, Object>>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        VerifyAuthenticationStepModel model = new VerifyAuthenticationStepModel();
        model.fromMap(context);

        byte[] dataFileBytes = VerifyAuthenticationCodeUtil.extractRequestDataBytes(model, stepLogger);

        RequestContext requestContext = RequestContext.builder()
                .httpMethod(HttpMethod.valueOf(model.getHttpMethod()))
                .requestObject(dataFileBytes)
                .authenticationHttpMethod(model.getHttpMethod())
                .authenticationRequestUri(model.getResourceId())
                .uri(model.getUriString())
                .build();

        StepContext<VerifyAuthenticationStepModel, ObjectResponse<Map<String, Object>>> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    /**
     * Log that the authentication code was successfully completed.
     */
    @Override
    public void logDryRun(StepLogger stepLogger) {
        stepLogger.writeItem(
                getStep().id() + "-authentication-code-computed",
                "Authentication code computed",
                "Activation authentication header was computed successfully",
                "OK",
                null

        );
    }

    @Override
    public void processResponse(StepContext<VerifyAuthenticationStepModel, ObjectResponse<Map<String, Object>>> stepContext) {
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-authentication-code-verified",
                "Authentication code verified",
                "Authentication code was verified successfully",
                "OK",
                null
        );
    }

}
