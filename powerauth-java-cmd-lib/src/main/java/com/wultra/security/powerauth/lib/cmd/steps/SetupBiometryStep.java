/*
 * PowerAuth Command-line utility
 * Copyright 2025 Wultra s.r.o.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.SetupBiometryStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.v4.request.RequestSharedSecret;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.lib.cmd.util.SharedSecretUtil;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Map;

/**
 * Helper class with setup biometry logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("setupBiometryStep")
public class SetupBiometryStep extends AbstractBaseStep<SetupBiometryStepModel, EncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    private static final ObjectMapper OBJECT_MAPPER = RestClientConfiguration.defaultMapper();

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public SetupBiometryStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                             ResultStatusService resultStatusService,
                             StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.BIOMETRY_SETUP, PowerAuthVersion.VERSION_4, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public SetupBiometryStep() {
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
    public StepContext<SetupBiometryStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final SetupBiometryStepModel model = new SetupBiometryStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/biometry/add")
                .uri(model.getUriString() + "/pa/v4/biometry/add")
                .build();

        final StepContext<SetupBiometryStepModel, EncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.ACTIVATION_SCOPE);
        final RequestSharedSecret sharedSecretRequest = SharedSecretUtil.buildSharedSecretRequest(
                sharedSecretAlgorithm,
                ctx -> stepContext.setSecurityContext(SimpleSecurityContext.builder().sharedSecretClientContext(ctx).build())
        );

        final byte[] requestBytesPayload = OBJECT_MAPPER.writeValueAsBytes(sharedSecretRequest);

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.SETUP_BIOMETRY, requestBytesPayload, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<SetupBiometryStepModel, EncryptedResponse> stepContext) throws Exception {

        final SharedSecretResponse responsePayload = decryptResponse(stepContext, SharedSecretResponse.class);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.ACTIVATION_SCOPE);
        final SharedSecretClientContext clientContext = ((SimpleSecurityContext) stepContext.getSecurityContext()).getSharedSecretClientContext();
        final SecretKey biometryFactorKey = SharedSecretUtil.deriveSharedSecret(responsePayload, clientContext, sharedSecretAlgorithm);
        final ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();
        resultStatusObject.setBiometryFactorKeyObject(biometryFactorKey);

        final SetupBiometryStepModel model = stepContext.getModel();
        model.setResultStatus(resultStatusObject);
        resultStatusService.save(model);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-biometry-added",
                "Biometry was setup successfully",
                "Biometry was successfully setup and new biometry factor key was saved",
                "OK",
                responsePayload);
    }



}
