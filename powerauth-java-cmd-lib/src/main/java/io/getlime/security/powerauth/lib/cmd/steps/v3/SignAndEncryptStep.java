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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.util.SecurityUtil;
import io.getlime.security.powerauth.lib.cmd.util.VerifySignatureUtil;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Sign and encrypt step signs request data and performs encryption using ECIES encryption in activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 * <p>
 *  @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 *  @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class SignAndEncryptStep extends AbstractBaseStep<VerifySignatureStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public SignAndEncryptStep(
            PowerAuthHeaderService powerAuthHeaderService,
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.SIGN_ENCRYPT, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    /**
     * Constructor for backward compatibility
     */
    public SignAndEncryptStep() {
        this(
                BackwardCompatibilityConst.POWER_AUTH_HEADER_SERVICE,
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<VerifySignatureStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .signatureHttpMethod(model.getHttpMethod())
                .signatureRequestUri(model.getResourceId())
                .uri(model.getUriString())
                .build();

        StepContext<VerifySignatureStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(stepLogger, model, requestContext);

        // Verify that HTTP method is set
        if (model.getHttpMethod() == null) {
            stepLogger.writeError("sign-encrypt-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
            stepLogger.writeDoneFailed("sign-encrypt-failed");
            return null;
        }

        // Verify HTTP method, only POST is supported
        if (!HttpMethod.POST.name().equals(model.getHttpMethod().toUpperCase())) {
            stepLogger.writeError("sign-encrypt-error-http-method-invalid", "Sign and Encrypt Request Failed", "Unsupported HTTP method: " + model.getHttpMethod().toUpperCase());
            stepLogger.writeDoneFailed("sign-encrypt-failed");
            return null;
        }

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            stepLogger.writeError("sign-encrypt-error-file", "Sign and Encrypt Request Failed", "Request data for encryption and signing is null.");
            stepLogger.writeDoneFailed("sign-encrypt-failed");
            return null;
        }

        stepLogger.writeItem(
                getStep().id() + "-request-prepare",
                "Preparing Request Data",
                "Following data will be encrypted",
                "OK",
                requestDataBytes
        );

        // Construct the signature base string data
        byte[] dataFileBytes = VerifySignatureUtil.extractRequestDataBytes(model, stepLogger);
        requestContext.setRequestObject(dataFileBytes);
        powerAuthHeaderService.addSignatureHeader(stepContext);

        // Encrypt the request
        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC, requestDataBytes);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<VerifySignatureStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        ResponseContext<EciesEncryptedResponse> responseContext = stepContext.getResponseContext();
        EciesEncryptor encryptor = stepContext.getEncryptor();
        final byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(encryptor, responseContext.getResponseBodyObject());

        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        stepContext.getModel().getResultStatus().setResponseData(decryptedMessage);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-response-decrypted",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                decryptedMessage
        );
    }

}
