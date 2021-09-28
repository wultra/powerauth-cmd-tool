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

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.RemoveTokenStepModel;
import io.getlime.security.powerauth.rest.api.model.request.v3.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.TokenRemoveResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;

/**
 * Helper class with token remove logic.
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
@Component(value = "removeTokenStepV3")
public class RemoveTokenStep extends AbstractBaseStep<RemoveTokenStepModel, ObjectResponse<TokenRemoveResponse>> {

    public static final ParameterizedTypeReference<ObjectResponse<TokenRemoveResponse>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<ObjectResponse<TokenRemoveResponse>>() { };

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    @Autowired
    public RemoveTokenStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.TOKEN_REMOVE, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public RemoveTokenStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<ObjectResponse<TokenRemoveResponse>> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<RemoveTokenStepModel, ObjectResponse<TokenRemoveResponse>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        RemoveTokenStepModel model = new RemoveTokenStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/token/remove")
                .uri(model.getUriString() + "/pa/v3/token/remove")
                .build();

        StepContext<RemoveTokenStepModel, ObjectResponse<TokenRemoveResponse>> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        incrementCounter(model);

        // Prepare request
        TokenRemoveRequest request = new TokenRemoveRequest();
        request.setTokenId(model.getTokenId());
        ObjectRequest<TokenRemoveRequest> objectRequest = new ObjectRequest<>(request);

        requestContext.setRequestObject(objectRequest);
        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<RemoveTokenStepModel, ObjectResponse<TokenRemoveResponse>> stepContext) throws Exception {
        ObjectResponse<TokenRemoveResponse> responseWrapper =
                Objects.requireNonNull(stepContext.getResponseContext().getResponseBodyObject());

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-token-removed",
                "Token successfully removed",
                "Token was successfully removed",
                "OK",
                responseWrapper.getResponseObject().getTokenId()

        );
    }

}
