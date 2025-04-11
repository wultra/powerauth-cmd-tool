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
package com.wultra.security.powerauth.lib.cmd.steps;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.TokenAndEncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
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
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 *  @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class TokenAndEncryptStep extends AbstractBaseStep<TokenAndEncryptStepModel, EncryptedResponse> {

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
    protected ParameterizedTypeReference<EncryptedResponse> getResponseTypeReference(PowerAuthVersion version) {
        return getResponseTypeReferenceEncrypted(version);
    }

    @Override
    public StepContext<TokenAndEncryptStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        TokenAndEncryptStepModel model = new TokenAndEncryptStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod(model.getHttpMethod())
                .uri(model.getUriString())
                .build();

        StepContext<TokenAndEncryptStepModel, EncryptedResponse> stepContext =
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

        // Encrypt the request

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.ACTIVATION_SCOPE_GENERIC, requestDataBytes, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<TokenAndEncryptStepModel, EncryptedResponse> stepContext) throws Exception {
        SecurityUtil.processEncryptedResponse(stepContext, getStep().id());
    }

}
