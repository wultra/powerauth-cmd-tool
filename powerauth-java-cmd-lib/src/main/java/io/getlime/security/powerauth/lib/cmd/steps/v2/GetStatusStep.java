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
package io.getlime.security.powerauth.lib.cmd.steps.v2;

import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.ExtendedActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.MapUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationStatusResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class with step for getting activation status.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak
 */
@Component(value = "getStatusStepV2")
public class GetStatusStep extends AbstractBaseStepV2 {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Constructor
     * @param stepLogger Step logger
     */
    @Autowired
    public GetStatusStep(StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_STATUS, PowerAuthVersion.VERSION_2, stepLogger);
    }

    /**
     * Constructor for backward compatibility
     */
    public GetStatusStep() {
        this(DEFAULT_STEP_LOGGER);
    }

    /**
     * Execute this step with given context
     *
     * @param context Provided context
     * @return Result status object, null in case of failure.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(Map<String, Object> context) {

        // Read properties from "context"
        final GetStatusStepModel model = new GetStatusStepModel();
        model.fromMap(context);

        // Prepare the activation URI
        final String uri = model.getUriString() + "/pa/activation/status";

        ResultStatusObject resultStatusObject = model.getResultStatus();

        // Get data from status
        final String activationId = resultStatusObject.getActivationId();
        final String transportMasterKeyBase64 = resultStatusObject.getTransportMasterKey();
        final SecretKey transportMasterKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKeyBase64));

        // Send the activation status request to the server
        final ActivationStatusRequest requestObject = new ActivationStatusRequest();
        requestObject.setActivationId(activationId);
        final ObjectRequest<ActivationStatusRequest> body = new ObjectRequest<>();
        body.setRequestObject(requestObject);

        try {

            final Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.putAll(model.getHeaders());

            stepLogger.writeServerCall("activation-status-request-sent", uri, "POST", requestObject, null, headers);

            ResponseEntity<ObjectResponse<ActivationStatusResponse>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<ObjectResponse<ActivationStatusResponse>> typeReference = new ParameterizedTypeReference<ObjectResponse<ActivationStatusResponse>>() {
            };
            try {
                responseEntity = restClient.post(uri, body, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                stepLogger.writeServerCallError("activation-status-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                stepLogger.writeDoneFailed("activation-status-failed");
                return null;
            }

            ObjectResponse<ActivationStatusResponse> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            stepLogger.writeServerCallOK("activation-status-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

            // Process the server response
            final ActivationStatusResponse responseObject = responseWrapper.getResponseObject();
            final byte[] cStatusBlob = Base64.getDecoder().decode(responseObject.getEncryptedStatusBlob());

            // Print the results
            final ActivationStatusBlobInfo statusBlobRaw = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
            final ExtendedActivationStatusBlobInfo statusBlob = ExtendedActivationStatusBlobInfo.copy(statusBlobRaw);

            final Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("activationId", activationId);
            objectMap.put("statusBlob", statusBlob);
            stepLogger.writeItem(
                    "activation-status-obtained",
                    "Activation Status",
                    "Activation status successfully obtained",
                    "OK",
                    objectMap
            );
            stepLogger.writeDoneOK("activation-status-success");

            return model.getResultStatus();
        } catch (Exception exception) {
            stepLogger.writeError("activation-status-error-generic", exception);
            stepLogger.writeDoneFailed("activation-status-failed");
            return null;
        }
    }

}
