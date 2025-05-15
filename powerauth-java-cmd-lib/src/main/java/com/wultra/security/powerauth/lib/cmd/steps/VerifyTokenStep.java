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

import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Step for the token validation activity.
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
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class VerifyTokenStep extends AbstractBaseStep<VerifyTokenStepModel, Map<String, Object>> {

    private static final ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE_REFERENCE = new ParameterizedTypeReference<>() {};

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public VerifyTokenStep(
            PowerAuthHeaderFactory powerAuthHeaderFactory,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.TOKEN_VALIDATE, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public VerifyTokenStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public ParameterizedTypeReference<Map<String, Object>> getResponseTypeReference(PowerAuthVersion version) {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<VerifyTokenStepModel, Map<String, Object>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .httpMethod(HttpMethod.valueOf(model.getHttpMethod()))
                .uri(model.getUriString())
                .build();

        StepContext<VerifyTokenStepModel, Map<String, Object>> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        Map<String, String> map = new HashMap<>();
        map.put("tokenId", model.getTokenId());
        map.put("tokenSecret", model.getTokenSecret());
        stepLogger.writeItem(
                "token-validate-start",
                "Token Digest Validation Started",
                null,
                "OK",
                map
        );

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        if (model.getHttpMethod() == null) {
            stepLogger.writeError("token-validate-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
            stepLogger.writeDoneFailed("token-validate-failed");
            return null;
        }

        // Construct the authentication base string data part based on HTTP method (GET requires different code).
        byte[] requestDataBytes = null;
        if (!HttpMethod.GET.name().equals(model.getHttpMethod().toUpperCase())) {
            // Read data input file
            requestDataBytes = model.getData();
            if (requestDataBytes == null || requestDataBytes.length == 0) {
                requestDataBytes = new byte[0];
                stepLogger.writeItem(
                        "token-validate-warning-empty-data",
                        "Empty data",
                        "Data file was not found, request will contain no data",
                        "WARNING",
                        null
                );
            }
        }

        requestContext.setRequestObject(requestDataBytes);
        return stepContext;
    }

    /**
     * Log information about the token value successfully computed.
     */
    @Override
    public void logDryRun(StepLogger stepLogger) {
        stepLogger.writeItem(
                getStep().id() + "-token-computed",
                "Token value computed (dry run)",
                "Token value header was computed successfully",
                "OK",
                null

        );
    }

    @Override
    public void processResponse(StepContext<VerifyTokenStepModel, Map<String, Object>> stepContext) {
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-digest-verified",
                "Token digest verified",
                "Token based authentication was successful",
                "OK",
                null
        );
    }

}
