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
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
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
import com.wultra.security.powerauth.lib.cmd.steps.model.ChangePasswordStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.lib.cmd.util.SharedSecretUtil;
import com.wultra.security.powerauth.rest.api.model.request.v4.SharedSecretRequest;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Console;
import java.util.Map;

/**
 * Helper class with password change logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("changePasswordStep")
public class ChangePasswordStep extends AbstractBaseStep<ChangePasswordStepModel, EncryptedResponse> {

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    private static final ObjectMapper OBJECT_MAPPER = RestClientConfiguration.defaultMapper();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Constructor
     * @param powerAuthHeaderFactory PowerAuth header factory
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public ChangePasswordStep(PowerAuthHeaderFactory powerAuthHeaderFactory,
                              ResultStatusService resultStatusService,
                              StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.PASSWORD_CHANGE, PowerAuthVersion.VERSION_4, resultStatusService, stepLoggerFactory);

        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public ChangePasswordStep() {
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
    public StepContext<ChangePasswordStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final ChangePasswordStepModel model = new ChangePasswordStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .authenticationHttpMethod("POST")
                .authenticationRequestUri("/pa/password/change")
                .uri(model.getUriString() + "/pa/v4/password/change")
                .build();

        final StepContext<ChangePasswordStepModel, EncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.ACTIVATION_SCOPE);
        final SharedSecretRequest sharedSecretRequest = SharedSecretUtil.buildSharedSecretRequest(
                sharedSecretAlgorithm,
                ctx -> stepContext.setSecurityContext(SimpleSecurityContext.builder().sharedSecretClientContext(ctx).build())
        );

        final byte[] requestBytesPayload = OBJECT_MAPPER.writeValueAsBytes(sharedSecretRequest);

        addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.CHANGE_PASSWORD, requestBytesPayload, EncryptorScope.ACTIVATION_SCOPE);

        powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);

        incrementCounter(model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<ChangePasswordStepModel, EncryptedResponse> stepContext) throws Exception {

        final SharedSecretResponse responsePayload = decryptResponse(stepContext, SharedSecretResponse.class);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, EncryptorScope.ACTIVATION_SCOPE);
        final SharedSecretClientContext clientContext = ((SimpleSecurityContext) stepContext.getSecurityContext()).getSharedSecretClientContext();
        final SecretKey knowledgeFactorKey = SharedSecretUtil.deriveSharedSecret(responsePayload, clientContext, sharedSecretAlgorithm);

        final char[] password;
        final ChangePasswordStepModel model = stepContext.getModel();
        if (model.getPasswordNew() == null) {
            final Console console = System.console();
            password = console.readPassword("Select a new password to encrypt the knowledge related key: ");
            Assert.state(password != null, "Not able to read a password from the console");
        } else {
            password = model.getPasswordNew().toCharArray();
        }

        final byte[] salt = KEY_GENERATOR.generateRandomBytes(16);
        final byte[] cKnowledgeFactorSecretKey = EncryptedStorageUtil.storeKnowledgeFactorKey(password, knowledgeFactorKey, salt, KEY_GENERATOR);
        final ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();
        resultStatusObject.setKnowledgeFactorKeyEncryptedBytes(cKnowledgeFactorSecretKey);
        resultStatusObject.setKnowledgeFactorKeySaltBytes(salt);
        model.setResultStatus(resultStatusObject);
        resultStatusService.save(model);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-password-changed",
                "Password was changed",
                "Password was successfully changed and new knowledge factor key was saved",
                "OK",
                Map.of("ecdhe", responsePayload.getEncapsulatedKeys().get(0),
                        "mlkem", responsePayload.getEncapsulatedKeys().get(1)));
    }

}
