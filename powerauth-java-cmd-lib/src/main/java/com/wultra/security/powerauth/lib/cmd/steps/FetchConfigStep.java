/*
 * PowerAuth Command-line utility
 * Copyright 2026 Wultra s.r.o.
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

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.FetchConfigStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Fetch config step fetches the secure configuration over end-to-end encryption in the application or
 * activation scope. The request payload is empty; the application (and, for the activation scope, the
 * activation) context is derived from the encryption header by the enrollment server.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("fetchConfigStep")
public class FetchConfigStep extends AbstractBaseStep<FetchConfigStepModel, EncryptedResponse> {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    /**
     * Empty request payload sent inside the end-to-end encrypted envelope.
     */
    private static final byte[] EMPTY_REQUEST = "{}".getBytes(StandardCharsets.UTF_8);

    /**
     * Constructor.
     * @param resultStatusService Result status service.
     * @param stepLoggerFactory Step logger factory.
     */
    @Autowired
    public FetchConfigStep(ResultStatusService resultStatusService, StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.CONFIG_FETCH, PowerAuthVersion.VERSION_4, resultStatusService, stepLoggerFactory);
    }

    /**
     * Constructor for backward compatibility.
     */
    public FetchConfigStep() {
        this(
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<EncryptedResponse> getResponseTypeReference(PowerAuthVersion version) {
        return getResponseTypeReferenceEncrypted(version);
    }

    @Override
    public StepContext<FetchConfigStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final FetchConfigStepModel model = new FetchConfigStepModel();
        model.fromMap(context);

        final EncryptorScope scope = switch (model.getScope()) {
            case "activation" -> EncryptorScope.ACTIVATION_SCOPE;
            case "application" -> EncryptorScope.APPLICATION_SCOPE;
            default -> null;
        };
        if (scope == null) {
            stepLogger.writeError("fetch-config-error-scope", "Fetch Configuration Failed", "Unsupported encryption scope: " + model.getScope());
            stepLogger.writeDoneFailed("fetch-config-failed");
            return null;
        }

        final String scopePath = scope == EncryptorScope.APPLICATION_SCOPE ? "application" : "activation";
        final RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v4/config/" + scopePath)
                .build();

        final StepContext<FetchConfigStepModel, EncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, scope);
        final boolean temporaryKeyFetchSucceeded = fetchTemporaryKey(stepContext, scope, sharedSecretAlgorithm);
        if (!temporaryKeyFetchSucceeded) {
            // Error is already logged
            return null;
        }

        final ResultStatusObject resultStatusObject = model.getResultStatus();
        final SecretKey temporarySharedSecret = stepContext.getTemporaryKeyContext().getTemporarySharedSecret();
        if (temporarySharedSecret == null) {
            stepLogger.writeError("fetch-config-error-temporary-key", "Fetch Configuration Failed", "Temporary key retrieval failed");
            stepLogger.writeDoneFailed("fetch-config-failed");
            return null;
        }

        final EncryptorId encryptorId;
        final EncryptorParameters encryptorParameters;
        final EncryptorSecrets encryptorSecrets;
        final PowerAuthEncryptionHttpHeader header;

        switch (scope) {
            case APPLICATION_SCOPE -> {
                encryptorId = EncryptorId.APPLICATION_SCOPE_GENERIC;
                encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, stepContext.getTemporaryKeyContext().getTemporaryKeyId());
                encryptorSecrets = new AeadSecrets(temporarySharedSecret.getEncoded(), model.getApplicationSecret());
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), model.getVersion().value());
            }
            case ACTIVATION_SCOPE -> {
                final String activationId = resultStatusObject.getActivationId();
                encryptorId = EncryptorId.ACTIVATION_SCOPE_GENERIC;
                encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), activationId, stepContext.getTemporaryKeyContext().getTemporaryKeyId());
                encryptorSecrets = new AeadSecrets(temporarySharedSecret.getEncoded(), model.getApplicationSecret(), Base64.getDecoder().decode(resultStatusObject.getSharedInfo2Key()));
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
            }
            default -> throw new IllegalStateException("Unsupported encryption scope: " + scope);
        }

        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, encryptorParameters, encryptorSecrets);

        addEncryptedRequest(stepContext, encryptor, EMPTY_REQUEST);

        final String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.getHttpHeaders().put(PowerAuthEncryptionHttpHeader.HEADER_NAME, headerValue);

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Fetching Configuration",
                "Sending an end-to-end encrypted request to fetch the configuration",
                "OK",
                requestContext.getRequestObject()
        );

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<FetchConfigStepModel, EncryptedResponse> stepContext) throws Exception {
        SecurityUtil.processEncryptedResponse(stepContext, getStep().id());
    }

}

