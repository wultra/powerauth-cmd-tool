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
package com.wultra.security.powerauth.lib.cmd.steps.v3;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.consts.BackwardCompatibilityConst;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthStep;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.StepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import com.wultra.security.powerauth.lib.cmd.logging.model.ExtendedActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.status.ResultStatusService;
import com.wultra.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import com.wultra.security.powerauth.lib.cmd.steps.context.RequestContext;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with step for getting activation status.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 *      <li>3.2</li>
 *      <li>3.3</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "getStatusStepV3")
public class GetStatusStep extends AbstractBaseStep<GetStatusStepModel, ObjectResponse<ActivationStatusResponse>> {

    /**
     * Attribute challenge
     */
    public static final String ATTRIBUTE_CHALLENGE = "challenge";

    private static final ParameterizedTypeReference<ObjectResponse<ActivationStatusResponse>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<>() {};

    private static final PowerAuthClientActivation ACTIVATION = new PowerAuthClientActivation();

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Constructor
     * @param resultStatusService Result status service
     * @param stepLoggerFactory Step logger factory
     */
    @Autowired
    public GetStatusStep(
            ResultStatusService resultStatusService,
            StepLoggerFactory stepLoggerFactory) {
        super(PowerAuthStep.ACTIVATION_STATUS, PowerAuthVersion.VERSION_3, resultStatusService, stepLoggerFactory);
    }

    /**
     * Constructor for backward compatibility
     */
    public GetStatusStep() {
        this(
                BackwardCompatibilityConst.RESULT_STATUS_SERVICE,
                BackwardCompatibilityConst.STEP_LOGGER_FACTORY
        );
    }

    @Override
    protected ParameterizedTypeReference<ObjectResponse<ActivationStatusResponse>> getResponseTypeReference() {
        return RESPONSE_TYPE_REFERENCE;
    }

    @Override
    public StepContext<GetStatusStepModel, ObjectResponse<ActivationStatusResponse>> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        final GetStatusStepModel model = new GetStatusStepModel();
        model.fromMap(context);

        // Decide whether "challenge" must be used in the request.
        final boolean useChallenge = !model.getVersion().equals(PowerAuthVersion.V3_0);

        final byte[] challenge = useChallenge ? KEY_GENERATOR.generateRandomBytes(16) : null;
        Map<String, Object> attributes = new HashMap<>();
        if (challenge != null) {
            attributes.put(ATTRIBUTE_CHALLENGE, challenge);
        }

        RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v3/activation/status")
                .build();

        StepContext<GetStatusStepModel, ObjectResponse<ActivationStatusResponse>> stepContext =
                buildStepContext(stepLogger, model, requestContext);
        stepContext.setAttributes(attributes);

        // Send the activation status request to the server
        final ActivationStatusRequest requestObject = new ActivationStatusRequest();
        requestObject.setActivationId(model.getResultStatus().getActivationId());
        requestObject.setChallenge(challenge != null ? Base64.getEncoder().encodeToString(challenge) : null);
        final ObjectRequest<ActivationStatusRequest> body = new ObjectRequest<>();
        body.setRequestObject(requestObject);

        requestContext.setRequestObject(body);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<GetStatusStepModel, ObjectResponse<ActivationStatusResponse>> stepContext) throws Exception {
        ResultStatusObject resultStatusObject = stepContext.getModel().getResultStatus();

        final boolean useChallenge = !stepContext.getModel().getVersion().equals(PowerAuthVersion.V3_0);

        // Process the server response
        final ActivationStatusResponse responseObject = stepContext.getResponseContext().getResponseBodyObject().getResponseObject();
        final byte[] cStatusBlob = Base64.getDecoder().decode(responseObject.getEncryptedStatusBlob());
        final byte[] cStatusBlobNonce = useChallenge ? Base64.getDecoder().decode(responseObject.getNonce()) : null;
        final Map<String, Object> customObject = responseObject.getCustomObject();
        byte[] challenge = (byte[]) stepContext.getAttributes().get(ATTRIBUTE_CHALLENGE);

        final SecretKey transportMasterKey = resultStatusObject.getTransportMasterKeyObject();
        if (transportMasterKey == null) {
            stepContext.getStepLogger().writeError(
                    getStep().id() + "-failed",
                    "Get Status Failed",
                    "transportMasterKey is null");
            return;
        }

        final ActivationStatusBlobInfo statusBlobRaw = ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challenge, cStatusBlobNonce, transportMasterKey);
        final ExtendedActivationStatusBlobInfo statusBlob = ExtendedActivationStatusBlobInfo.copy(statusBlobRaw);

        final Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("activationId", resultStatusObject.getActivationId());
        objectMap.put("statusBlob", statusBlob);
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
