/*
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.logging.model.ExtendedActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.base.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with step for getting activation status.
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
@Component("getStatusStep")
public class GetStatusStep extends AbstractBaseStep<GetStatusStepModel, Object> {

    private static final ObjectMapper OBJECT_MAPPER = RestClientConfiguration.defaultMapper();

    private final PowerAuthHeaderFactory powerAuthHeaderFactory;

    /**
     * Attribute challenge
     */
    public static final String ATTRIBUTE_CHALLENGE = "challenge";

    private static final ParameterizedTypeReference<ObjectResponse<com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse>> RESPONSE_TYPE_REFERENCE_V3 =
            new ParameterizedTypeReference<>() {};

    private static final com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation CLIENT_ACTIVATION_V3 = new com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation();
    private static final com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation CLIENT_ACTIVATION_V4 = new com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Constructor
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     * @param powerAuthHeaderFactory PowerAuth header factory
     */
    @Autowired
    public GetStatusStep(
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory,
            PowerAuthHeaderFactory powerAuthHeaderFactory) {
        super(PowerAuthStep.ACTIVATION_STATUS, PowerAuthVersion.ALL_VERSIONS, resultStatusService, stepLoggerFactory);
        this.powerAuthHeaderFactory = powerAuthHeaderFactory;
    }

    /**
     * Constructor for backward compatibility
     */
    public GetStatusStep() {
        this(
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY,
                BackwardCompatibilityConst.POWER_AUTH_HEADER_FACTORY
        );
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    protected ParameterizedTypeReference getResponseTypeReference(PowerAuthVersion version) {
        return switch (version.getMajorVersion()) {
            case 3 -> RESPONSE_TYPE_REFERENCE_V3;
            case 4 -> getResponseTypeReferenceEncrypted(version);
            default -> throw new IllegalArgumentException("Unsupported version: " + version);
        };
    }

    @Override
    public StepContext<GetStatusStepModel, Object> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final GetStatusStepModel model = new GetStatusStepModel();
        model.fromMap(context);

        // Decide whether "challenge" must be used in the request.
        final boolean useChallenge = !model.getVersion().equals(PowerAuthVersion.V3_0);

        final byte[] challenge = useChallenge ? KEY_GENERATOR.generateRandomBytes(16) : null;
        final Map<String, Object> attributes = new HashMap<>();
        if (challenge != null) {
            attributes.put(ATTRIBUTE_CHALLENGE, challenge);
        }

        final int majorVersion = model.getVersion().getMajorVersion();
        final RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v" + majorVersion + "/activation/status")
                .build();

        final StepContext<GetStatusStepModel, Object> stepContext =
                buildStepContext(stepLogger, model, requestContext);
        stepContext.setAttributes(attributes);

        return switch (majorVersion) {
            case 3 -> {
                final com.wultra.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest requestObject = new com.wultra.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest();
                requestObject.setActivationId(model.getResultStatus().getActivationId());
                requestObject.setChallenge(challenge != null ? Base64.getEncoder().encodeToString(challenge) : null);
                final ObjectRequest<com.wultra.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest> body = new ObjectRequest<>();
                body.setRequestObject(requestObject);
                requestContext.setRequestObject(body);
                yield stepContext;
            }
            case 4 -> {
                final byte[] statusRequest = "{}".getBytes(StandardCharsets.UTF_8);
                addEncryptedRequest(stepContext, model.getApplicationKey(), model.getApplicationSecret(), EncryptorId.ACTIVATION_SCOPE_GENERIC, statusRequest, EncryptorScope.ACTIVATION_SCOPE);
                powerAuthHeaderFactory.getHeaderProvider(model).addHeader(stepContext);
                yield stepContext;
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        };
    }

    @Override
    @SuppressWarnings("unchecked")
    public void processResponse(StepContext<GetStatusStepModel, Object> stepContext) throws Exception {
        ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();

        final ExtendedActivationStatusBlobInfo statusBlobInfo;
        final Map<String, Object> customObject;
        switch (stepContext.getModel().getVersion().getMajorVersion()) {
            case 3 -> {
                final boolean useChallenge = !stepContext.getModel().getVersion().equals(PowerAuthVersion.V3_0);

                // Process the server response
                final com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse responseObject = ((ObjectResponse<com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse>) stepContext.getResponseContext().getResponseBodyObject()).getResponseObject();
                final byte[] cStatusBlob = Base64.getDecoder().decode(responseObject.getEncryptedStatusBlob());
                final byte[] cStatusBlobNonce = useChallenge ? Base64.getDecoder().decode(responseObject.getNonce()) : null;
                customObject = responseObject.getCustomObject();
                byte[] challenge = (byte[]) stepContext.getAttributes().get(ATTRIBUTE_CHALLENGE);

                final SecretKey transportMasterKey = resultStatusObject.getTransportMasterKeyObject();
                if (transportMasterKey == null) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-failed",
                            "Get Status Failed",
                            "The transportMasterKey is null");
                    return;
                }

                final ActivationStatusBlobInfo statusBlobRaw = CLIENT_ACTIVATION_V3.getStatusFromEncryptedBlob(cStatusBlob, challenge, cStatusBlobNonce, transportMasterKey);
                statusBlobInfo = ExtendedActivationStatusBlobInfo.copy(statusBlobRaw);
            }
            case 4 -> {
                final SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
                final AeadEncryptedResponse aeadResponse = (AeadEncryptedResponse) stepContext.getResponseContext().getResponseBodyObject();
                final byte[] decryptedBytes = securityContext.getEncryptor().decryptResponse(new AeadEncryptedResponse(
                        aeadResponse.getEncryptedData(),
                        aeadResponse.getTimestamp()
                ));
                final com.wultra.security.powerauth.rest.api.model.response.v4.ActivationStatusResponse statusResponse = OBJECT_MAPPER.readValue(decryptedBytes, com.wultra.security.powerauth.rest.api.model.response.v4.ActivationStatusResponse.class);
                final byte[] statusBlob = Base64.getDecoder().decode(statusResponse.getActivationStatus());
                final byte[] statusBlobData = Arrays.copyOfRange(statusBlob, 0, 48);
                final byte[] statusBlobMac = Arrays.copyOfRange(statusBlob, 48, 80);
                // Verify MAC
                if (!CLIENT_ACTIVATION_V4.verifyStatusMac(statusBlobData, statusBlobMac, resultStatusObject.getStatusBlobMacKeyObject(), ProtocolVersion.fromValue(stepContext.getModel().getVersion().value()))) {
                    stepContext.getStepLogger().writeError(
                            getStep().id() + "-failed",
                            "MAC verification failed",
                            "Failed MAC verification for status blob");
                    return;
                }
                final ActivationStatusBlobInfo statusBlobRaw = CLIENT_ACTIVATION_V4.getStatusFromBlob(statusBlobData);
                statusBlobInfo = ExtendedActivationStatusBlobInfo.copy(statusBlobRaw);
                customObject = statusResponse.getCustomObject();
            }
            default -> throw new IllegalArgumentException("Unsupported version: " + stepContext.getModel().getVersion());
        }


        final Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("statusBlob", statusBlobInfo);
        objectMap.put("customObject", customObject);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-obtained",
                "Activation Status",
                "Activation status successfully obtained",
                "OK",
                objectMap
        );
    }

}
