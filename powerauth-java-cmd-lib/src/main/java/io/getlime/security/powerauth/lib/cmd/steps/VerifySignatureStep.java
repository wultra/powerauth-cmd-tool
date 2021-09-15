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

import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.VerifySignatureUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
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
public class VerifySignatureStep extends AbstractBaseStep<VerifySignatureStepModel, Map<String, Object>> {

    ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<Map<String, Object>>() { };

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public VerifySignatureStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLogger stepLogger) {
        super(PowerAuthStep.SIGNATURE_VERIFY, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    /**
     * Constructor for backward compatibility
     */
    public VerifySignatureStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_SERVICE,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER
        );
    }

    @Override
    public ParameterizedTypeReference<Map<String, Object>> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<VerifySignatureStepModel, Map<String, Object>> prepareStepContext(Map<String, Object> context) throws Exception {
        VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.fromMap(context);

        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);

        RequestContext requestContext = RequestContext.builder()
                .httpMethod(model.getHttpMethod())
                .requestObject(dataFileBytes)
                .signatureHttpMethod(model.getHttpMethod())
                .signatureRequestUri(model.getResourceId())
                .uri(model.getUriString())
                .build();

        StepContext<VerifySignatureStepModel, Map<String, Object>> stepContext =
                buildStepContext(model, requestContext);

        powerAuthHeaderService.addSignatureHeader(stepContext, true);

        incrementCounter(model);

        return stepContext;
    }

    /**
     * Log that the signature was successfully completed.
     */
    public void logDryRun() {
        stepLogger.writeItem(
                getStep().id() + "-signature-computed",
                "Signature computed",
                "Activation signature header was computed successfully",
                "OK",
                null

        );
    }

    @Override
    public void processResponse(StepContext<VerifySignatureStepModel, Map<String, Object>> stepContext) throws Exception {
        stepLogger.writeItem(
                getStep().id() + "-signature-verified",
                "Signature verified",
                "Activation signature was verified successfully",
                "OK",
                null
        );
    }

}
