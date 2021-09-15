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
package io.getlime.security.powerauth.lib.cmd.steps;

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Step for the token validation activity.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class VerifyTokenStep extends AbstractBaseStep<VerifyTokenStepModel, Map<String, Object>> {

    ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<Map<String, Object>>() { };

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public VerifyTokenStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLogger stepLogger) {
        super(PowerAuthStep.TOKEN_VALIDATE, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    @Override
    public ParameterizedTypeReference<Map<String, Object>> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<VerifyTokenStepModel, Map<String, Object>> prepareStepContext(Map<String, Object> context) throws Exception {
        VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .httpMethod(model.getHttpMethod())
                .uri(model.getUriString())
                .build();

        StepContext<VerifyTokenStepModel, Map<String, Object>> stepContext =
                buildStepContext(model, requestContext);

        // Initiate the step sequence
        logTokenVerificationStart(model.getTokenId(), model.getTokenSecret());

        powerAuthHeaderService.addTokenHeader(requestContext, model);

        if (model.getHttpMethod() == null) {
            if (stepLogger != null) {
                stepLogger.writeError("token-validate-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
                stepLogger.writeDoneFailed("token-validate-failed");
            }
            return null;
        }

        // Construct the signature base string data part based on HTTP method (GET requires different code).
        byte[] requestDataBytes = null;
        if (!"GET".equals(model.getHttpMethod().toUpperCase())) {
            // Read data input file
            requestDataBytes = model.getData();
            if (requestDataBytes == null || requestDataBytes.length == 0) {
                requestDataBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "token-validate-warning-empty-data",
                            "Empty data",
                            "Data file was not found, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        }

        requestContext.setRequestObject(requestDataBytes);
        return stepContext;
    }

    /**
     * Log the initiation of the token verification steps.
     *
     * @param tokenId     Token ID.
     * @param tokenSecret Token secret.
     */
    private void logTokenVerificationStart(String tokenId, String tokenSecret) {
        // TODO rely on default step start logging
        Map<String, String> map = new HashMap<>();
        map.put("TOKEN_ID", tokenId);
        map.put("TOKEN_SECRET", tokenSecret);
        stepLogger.writeItem(
                "token-validate-start",
                "Token Digest Validation Started",
                null,
                "OK",
                map
        );
    }

    /**
     * Log information about the token value successfully computed.
     */
    @Override
    public void logDryRun() {
        stepLogger.writeItem(
                getStep().id() + "-token-computed",
                "Token value computed",
                "Token value header was computed successfully",
                "OK",
                null

        );
    }

    @Override
    public void processResponse(StepContext<VerifyTokenStepModel, Map<String, Object>> responseContext) throws Exception {
        stepLogger.writeItem(
                getStep().id() + "-digest-verified",
                "Token digest verified",
                "Token based authentication was successful",
                "OK",
                null
        );
    }

}
