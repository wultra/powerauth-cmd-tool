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
package com.wultra.security.powerauth.lib.cmd.steps.v3;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import com.wultra.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Helper class with token creation logic.
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
@Component(value = "createTokenStepV3")
public class CreateTokenStep extends AbstractBaseStep<CreateTokenStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public CreateTokenStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                           ResultStatusService resultStatusService,
                           StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.TOKEN_CREATE, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public CreateTokenStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<CreateTokenStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        CreateTokenStepModel model = new CreateTokenStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod("POST")
                .signatureRequestUri("/pa/token/create")
                .uri(model.getUriString() + "/pa/v3/token/create")
                .build();

        StepContext<CreateTokenStepModel, EciesEncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.CREATE_TOKEN, PowerAuthConst.EMPTY_JSON_BYTES, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<CreateTokenStepModel, EciesEncryptedResponse> stepContext) throws Exception {

        final TokenResponsePayload tokenResponsePayload = decryptResponse(stepContext, TokenResponsePayload.class);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-token-obtained",
                "Token successfully obtained",
                "Token was successfully generated and decrypted",
                "OK",
                Map.of("tokenId", tokenResponsePayload.getTokenId(),
                        "tokenSecret",tokenResponsePayload.getTokenSecret())
        );
    }

}
