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

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.VerifySignatureUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Helper class with signature verification logic.
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
 * @author Petr Dvorak
 */
@Component
public class VerifySignatureStep extends AbstractBaseStep<VerifySignatureStepModel, ObjectResponse<Map<String, Object>>> {

    ParameterizedTypeReference<ObjectResponse<Map<String, Object>>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<ObjectResponse<Map<String, Object>>>() { };

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public VerifySignatureStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.SIGNATURE_VERIFY, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    /**
     * Constructor for backward compatibility
     */
    public VerifySignatureStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_SERVICE,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    public ParameterizedTypeReference<ObjectResponse<Map<String, Object>>> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<VerifySignatureStepModel, ObjectResponse<Map<String, Object>>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.fromMap(context);

        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);

        RequestContext requestContext = RequestContext.builder()
                .httpMethod(HttpMethod.valueOf(model.getHttpMethod()))
                .requestObject(dataFileBytes)
                .signatureHttpMethod(model.getHttpMethod())
                .signatureRequestUri(model.getResourceId())
                .uri(model.getUriString())
                .build();

        StepContext<VerifySignatureStepModel, ObjectResponse<Map<String, Object>>> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        powerAuthHeaderService.addSignatureHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    /**
     * Log that the signature was successfully completed.
     */
    @Override
    public void logDryRun(StepLogger stepLogger) {
        stepLogger.writeItem(
                getStep().id() + "-signature-computed",
                "Signature computed",
                "Activation signature header was computed successfully",
                "OK",
                null

        );
    }

    @Override
    public void processResponse(StepContext<VerifySignatureStepModel, ObjectResponse<Map<String, Object>>> stepContext) throws Exception {
        stepContext.getStepLogger().writeItem(
                getStep().id() + "-signature-verified",
                "Signature verified",
                "Activation signature was verified successfully",
                "OK",
                null
        );
    }

}
