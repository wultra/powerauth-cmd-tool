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
package com.wultra.security.powerauth.lib.cmd.steps.v3;

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Map;

import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.TEMPORARY_KEY_ID;
import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.TEMPORARY_PUBLIC_KEY;

/**
 * Encrypt step encrypts request data using ECIES encryption in application or activation scope.
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
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "encryptStepV3")
public class EncryptStep extends AbstractBaseStep<EncryptStepModel, EciesEncryptedResponse> {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Constructor
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public EncryptStep(ResultStatusService resultStatusService, StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ENCRYPT, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);
    }

    /**
     * Constructor for backward compatibility
     */
    public EncryptStep() {
        this(
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<EncryptStepModel, EciesEncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        EncryptStepModel model = new EncryptStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.<EncryptStepModel>builder()
                .uri(model.getUriString())
                .build();

        StepContext<EncryptStepModel, EciesEncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            stepLogger.writeError("encrypt-error-file", "Encrypt Request Failed", "Request data for encryption was null.");
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Preparing Request Data",
                "Following data will be encrypted",
                "OK",
                requestDataBytes
        );

        final EncryptorScope scope = switch (model.getScope()) {
            case "activation":
                yield EncryptorScope.ACTIVATION_SCOPE;
            case "application":
                yield EncryptorScope.APPLICATION_SCOPE;
            default:
                yield null;
        };
        if (scope == null) {
            stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported encryption scope: " + model.getScope());
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }
        fetchTemporaryKey(stepContext, scope);
        final String temporaryKeyId =  (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID);
        final String temporaryPublicKey = (String) stepContext.getAttributes().get(TEMPORARY_PUBLIC_KEY);

        // Prepare the encryption header
        final EncryptorId encryptorId;
        final ClientEncryptor encryptor;
        final PowerAuthEncryptionHttpHeader header;
        switch (scope) {
            case APPLICATION_SCOPE -> {
                final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                        model.getMasterPublicKey() :
                        KEY_CONVERTOR.convertBytesToPublicKey(java.util.Base64.getDecoder().decode(temporaryPublicKey));
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/application
                encryptorId = EncryptorId.APPLICATION_SCOPE_GENERIC;
                final EncryptorParameters encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId);
                final ClientEncryptorSecrets encryptorSecrets = new ClientEncryptorSecrets(encryptionPublicKey, model.getApplicationSecret());
                encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, encryptorParameters, encryptorSecrets);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), model.getVersion().value());
            }
            case ACTIVATION_SCOPE -> {
                final ResultStatusObject resultStatusObject = model.getResultStatus();
                final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                        resultStatusObject.getServerPublicKeyObject() :
                        KEY_CONVERTOR.convertBytesToPublicKey(java.util.Base64.getDecoder().decode(temporaryPublicKey));
                encryptorId = EncryptorId.ACTIVATION_SCOPE_GENERIC;
                encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                        encryptorId,
                        new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), resultStatusObject.getActivationId(), temporaryKeyId),
                        new ClientEncryptorSecrets(encryptionPublicKey, model.getApplicationSecret(), Base64.decode(resultStatusObject.getTransportMasterKey()))
                );
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/activation
                final String activationId = model.getResultStatus().getActivationId();
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
            }
            default -> {
                stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported encryption scope: " + model.getScope());
                stepLogger.writeDoneFailed("encrypt-failed");
                return null;
            }
        }

        addEncryptedRequest(stepContext, encryptor, requestDataBytes);

        String headerValue = header.buildHttpHeader();
        requestContext.setAuthorizationHeader(headerValue);
        requestContext.getHttpHeaders().put(PowerAuthEncryptionHttpHeader.HEADER_NAME, headerValue);

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Encrypting Request Data",
                "Following data is sent to intermediate server",
                "OK",
                requestContext.getRequestObject()
        );

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<EncryptStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        SecurityUtil.processEncryptedResponse(stepContext, getStep().id());
    }
}
