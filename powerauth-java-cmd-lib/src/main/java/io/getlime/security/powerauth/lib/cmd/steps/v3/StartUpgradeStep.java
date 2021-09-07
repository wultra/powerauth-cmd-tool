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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.UpgradeResponsePayload;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Step for starting upgrade to PowerAuth protocol version 3.0.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StartUpgradeStep implements BaseStep {

    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();
    private static final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Execute this step with given context.
     * @param context Provided context.
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        StartUpgradeStepModel model = new StartUpgradeStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "upgrade-start-started",
                    "Upgrade Started",
                    null,
                    "OK",
                    null
            );
        }

        ResultStatusObject resultStatusObject = model.getResultStatusObject();

        final String uri = model.getUriString() + "/pa/v3/upgrade/start";
        final String applicationKey = model.getApplicationKey();
        final String activationId = resultStatusObject.getActivationId();

        // Prepare ECIES encryptor and encrypt request data with sharedInfo1 = /pa/upgrade
        final boolean useIv = !"3.0".equals(model.getVersion());
        byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        byte[] transportMasterKeyBytes = resultStatusObject.getTransportMasterKey().getEncoded();
        byte[] serverPublicKeyBytes = resultStatusObject.getServerPublicKey().getEncoded();
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, EciesSharedInfo1.UPGRADE);
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8), useIv);

        // Prepare encrypted request
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        final String nonce = useIv ? BaseEncoding.base64().encode(eciesCryptogram.getNonce()) : null;
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);

        byte[] requestBytes = mapper.writeValueAsBytes(request);

        // Prepare the encryption header
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader(applicationKey, activationId, model.getVersion());
        String httpEncryptionHeader = header.buildHttpHeader();

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthEncryptionHttpHeader.HEADER_NAME, httpEncryptionHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall("upgrade-start-request-sent", uri, "POST", request, headers);
            }

            ResponseEntity<EciesEncryptedResponse> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<EciesEncryptedResponse> typeReference = new ParameterizedTypeReference<EciesEncryptedResponse>() {};
            try {
                responseEntity = restClient.post(uri, requestBytes, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("upgrade-start-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("upgrade-start-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponse = Objects.requireNonNull(responseEntity.getBody());
            if (stepLogger != null) {
                stepLogger.writeServerCallOK("upgrade-start-response-received", encryptedResponse, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            // Decrypt response
            byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
            byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
            final EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

            byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

            final UpgradeResponsePayload upgradeResponsePayload = mapper.readValue(decryptedBytes, UpgradeResponsePayload.class);

            // Store the activation status (updated counter)
            model.getResultStatusObject().setCtrDataBase64(upgradeResponsePayload.getCtrData());
            String statusFormatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
            try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                file.write(statusFormatted);
            }

            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("ctrData", upgradeResponsePayload.getCtrData());

            if (stepLogger != null) {
                stepLogger.writeItem(
                        "upgrade-start-completed",
                        "Upgrade start step successfully completed",
                        "Upgrade start step was successfully completed",
                        "OK",
                        objectMap

                );
                stepLogger.writeDoneOK("upgrade-start-success");
            }

            return model.getResultStatusObject();
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("upgrade-start-error-generic", exception);
                stepLogger.writeDoneFailed("upgrade-start-failed");
            }
            return null;
        }
    }

}
