/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.io.BaseEncoding;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class with step for getting activation status.
 *
 * @author Petr Dvorak
 *
 */
public class GetStatusStep implements BaseStep {

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        String uriString = (String) context.get("URI_STRING");
        JSONObject resultStatusObject = (JSONObject) context.get("STATUS_OBJECT");

        stepLogger.writeItem(
                "Activation Status Check Started",
                null,
                "OK",
                null
        );

        // Prepare the activation URI
        String uri = uriString + "/pa/activation/status";

        // Get data from status
        String activationId = (String) resultStatusObject.get("activationId");
        String transportMasterKeyBase64 = (String) resultStatusObject.get("transportMasterKey");
        SecretKey transportMasterKey = keyConversion.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKeyBase64));

        // Send the activation status request to the server
        ActivationStatusRequest requestObject = new ActivationStatusRequest();
        requestObject.setActivationId(activationId);
        PowerAuthApiRequest<ActivationStatusRequest> body = new PowerAuthApiRequest<>();
        body.setRequestObject(requestObject);

        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");

            stepLogger.writeServerCall(uri, "POST", requestObject, headers);

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(body)
                    .asString();

            TypeReference<PowerAuthApiResponse<ActivationStatusResponse>> typeReference = new TypeReference<PowerAuthApiResponse<ActivationStatusResponse>>() {};
            PowerAuthApiResponse<ActivationStatusResponse> responseWrapper = RestClientConfiguration
                    .defaultMapper()
                    .readValue(response.getRawBody(), typeReference);

            if (response.getStatus() == 200) {
                stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

                // Process the server response
                ActivationStatusResponse responseObject = responseWrapper.getResponseObject();
                byte[] cStatusBlob = BaseEncoding.base64().decode(responseObject.getEncryptedStatusBlob());

                // Print the results
                ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);

                Map<String, Object> objectMap = new HashMap<>();
                objectMap.put("activationId", activationId);
                objectMap.put("statusBlob", statusBlob);
                stepLogger.writeItem(
                        "Avtivation Status",
                        "Activation status successfully obtained",
                        "OK",
                        objectMap
                );

                stepLogger.writeDoneOK();
                return resultStatusObject;
            } else {
                stepLogger.writeServerCallError(response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                stepLogger.writeDoneFailed();
                return null;
            }
        } catch (UnirestException exception) {
            stepLogger.writeServerCallConnectionError(exception);
            stepLogger.writeDoneFailed();
            return null;
        } catch (Exception exception) {
            stepLogger.writeError(exception);
            stepLogger.writeDoneFailed();
            return null;
        }
    }

}
