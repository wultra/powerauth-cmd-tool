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

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Map;

import static com.wultra.security.powerauth.lib.cmd.util.TemporaryKeyUtil.*;

/**
 * Encrypt step encrypts request data using ECIES encryption in application or activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("encryptStep")
public class EncryptStep extends AbstractBaseStep<EncryptStepModel, EncryptedResponse> {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Constructor
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public EncryptStep(ResultStatusService resultStatusService, StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ENCRYPT, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);
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
    protected ParameterizedTypeReference<EncryptedResponse> getResponseTypeReference(PowerAuthVersion version) {
        return getResponseTypeReferenceEncrypted(version);
    }

    @Override
    public StepContext<EncryptStepModel, EncryptedResponse> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final EncryptStepModel model = new EncryptStepModel();
        model.fromMap(context);

        final RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString())
                .build();

        final StepContext<EncryptStepModel, EncryptedResponse> stepContext = buildStepContext(stepLogger, model, requestContext);

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
        final SharedSecretAlgorithm sharedSecretAlgorithm = SecurityUtil.resolveSharedSecretAlgorithm(stepContext, scope);
        fetchTemporaryKey(stepContext, scope, sharedSecretAlgorithm);
        final String temporaryKeyId = (String) stepContext.getAttributes().get(TEMPORARY_KEY_ID);
        final ResultStatusObject resultStatusObject = model.getResultStatus();

        // Prepare the encryption header
        final EncryptorId encryptorId;
        final ClientEncryptor<EncryptedRequest, EncryptedResponse> encryptor;
        final PowerAuthEncryptionHttpHeader header;
        final EncryptorParameters encryptorParameters;
        final EncryptorSecrets encryptorSecrets;

        switch (scope) {
            case APPLICATION_SCOPE -> {
                switch (model.getVersion().getMajorVersion()) {
                    case 3 -> {
                        final String temporaryPublicKey = (String) stepContext.getAttributes().get(TEMPORARY_PUBLIC_KEY);
                        final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                                model.getMasterPublicKeyP256() :
                                KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, java.util.Base64.getDecoder().decode(temporaryPublicKey));
                        encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId);
                        encryptorSecrets = new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret());
                    }
                    case 4 -> {
                        final SecretKey temporarySharedSecret = (SecretKey) stepContext.getAttributes().get(TEMPORARY_SHARED_SECRET);
                        encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), null, temporaryKeyId);
                        encryptorSecrets = new AeadSecrets(temporarySharedSecret.getEncoded(), model.getApplicationSecret());
                    }
                    default -> {
                        stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported version: " + model.getVersion());
                        stepLogger.writeDoneFailed("encrypt-failed");
                        return null;
                    }
                }
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/application
                encryptorId = EncryptorId.APPLICATION_SCOPE_GENERIC;
                encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, encryptorParameters, encryptorSecrets);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), model.getVersion().value());
            }
            case ACTIVATION_SCOPE -> {
                switch (model.getVersion().getMajorVersion()) {
                    case 3 -> {
                        final String temporaryPublicKey = (String) stepContext.getAttributes().get(TEMPORARY_PUBLIC_KEY);
                        final PublicKey encryptionPublicKey = temporaryPublicKey == null ?
                                resultStatusObject.getServerPublicKeyObject() :
                                KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, java.util.Base64.getDecoder().decode(temporaryPublicKey));
                        encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), resultStatusObject.getActivationId(), temporaryKeyId);
                        encryptorSecrets = new ClientEciesSecrets(encryptionPublicKey, model.getApplicationSecret(), Base64.decode(resultStatusObject.getTransportMasterKey()));
                    }
                    case 4 -> {
                        final SecretKey temporarySharedSecret = (SecretKey) stepContext.getAttributes().get(TEMPORARY_SHARED_SECRET);
                        encryptorParameters = new EncryptorParameters(model.getVersion().value(), model.getApplicationKey(), resultStatusObject.getActivationId(), temporaryKeyId);
                        encryptorSecrets = new AeadSecrets(temporarySharedSecret.getEncoded(), model.getApplicationSecret(), Base64.decode(resultStatusObject.getTransportMasterKey()));
                    }
                    default -> {
                        stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported version: " + model.getVersion());
                        stepLogger.writeDoneFailed("encrypt-failed");
                        return null;
                    }
                }
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/activation
                encryptorId = EncryptorId.ACTIVATION_SCOPE_GENERIC;
                encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, encryptorParameters, encryptorSecrets);
                final String activationId = model.getResultStatus().getActivationId();
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
            }
            default -> {
                encryptor = null;
                header = null;
            }
        }

        addEncryptedRequest(stepContext, encryptor, requestDataBytes);

        final String headerValue = header.buildHttpHeader();
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
    public void processResponse(StepContext<EncryptStepModel, EncryptedResponse> stepContext) throws Exception {
        SecurityUtil.processEncryptedResponse(stepContext, getStep().id());
    }
}
