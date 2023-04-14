/*
 * PowerAuth Command-line utility
 * Copyright 2022 Wultra s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.TokenAndEncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.util.EncryptionUtil;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Token and encrypt step generates token authentication for request data and performs encryption using ECIES encryption in activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 *  @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class TokenAndEncryptStep extends AbstractBaseStep<TokenAndEncryptStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor.
     * @param powerAuthHeaderFactory PowerAuth header factory.
     * @param resultStatusService Result status service.
     * @param stepLoggerFactory Step logger factory.
     */
    @Autowired
    public TokenAndEncryptStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.TOKEN_ENCRYPT, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public TokenAndEncryptStep() {
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
    public StepContext<TokenAndEncryptStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        TokenAndEncryptStepModel model = new TokenAndEncryptStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod(model.getHttpMethod())
                .uri(model.getUriString())
                .build();

        StepContext<TokenAndEncryptStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Verify that HTTP method is set
        if (model.getHttpMethod() == null) {
            stepLogger.writeError(getStep().id() + "-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
            stepLogger.writeDoneFailed("token-encrypt-failed");
            return null;
        }

        // Verify HTTP method, GET is not supported
        if (HttpMethod.GET.name().equals(model.getHttpMethod().toUpperCase())) {
            stepLogger.writeError(getStep().id() + "-error-http-method-invalid", "Token and Encrypt Request Failed", "Unsupported HTTP method: " + model.getHttpMethod().toUpperCase());
            stepLogger.writeDoneFailed("token-encrypt-failed");
            return null;
        }

        // Read data which needs to be encrypted
        byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null || requestDataBytes.length == 0) {
            requestDataBytes = new byte[0];
            stepLogger.writeItem(
                    getStep().id() + "-warning-empty-data",
                    "Empty data",
                    "Data file was not found, signature will contain no data",
                    "WARNING",
                    null
            );
        }

        stepLogger.writeItem(
                getStep().id() + "-request-prepare",
                "Preparing Request Data",
                "Following data will be encrypted",
                "OK",
                requestDataBytes
        );

        requestContext.setRequestObject(requestDataBytes);
        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        // Encrypt the request
        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC, requestDataBytes);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<TokenAndEncryptStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        EncryptionUtil.processEncryptedResponse(stepContext, getStep().id());
    }

}
