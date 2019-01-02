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
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.JsonUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.UpgradeResponsePayload;
import org.json.simple.JSONObject;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Step for starting upgrade to PowerAuth protocol version 3.0.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StartUpgradeStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
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
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        StartUpgradeStepModel model = new StartUpgradeStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Upgrade Started",
                    null,
                    "OK",
                    null
            );
        }

        final String uri = model.getUriString() + "/pa/v3/upgrade/start";
        final String applicationKey = model.getApplicationKey();
        final String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");

        // Prepare ECIES encryptor and encrypt request data with sharedInfo1 = /pa/upgrade
        byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, EciesSharedInfo1.UPGRADE);
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));

        // Prepare encrypted request
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);

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
                stepLogger.writeServerCall(uri, "POST", request, headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(requestBytes)
                    .asString();

            if (response.getStatus() == 200) {
                EciesEncryptedResponse encryptedResponse = mapper.readValue(response.getRawBody(), EciesEncryptedResponse.class);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(encryptedResponse, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                // Decrypt response
                byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
                byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
                final EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

                byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

                final UpgradeResponsePayload upgradeResponsePayload = mapper.readValue(decryptedBytes, UpgradeResponsePayload.class);

                // Store the activation status (updated counter)
                model.getResultStatusObject().put("ctrData", upgradeResponsePayload.getCtrData());
                String statusFormatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(statusFormatted);
                }

                Map<String, Object> objectMap = new HashMap<>();
                objectMap.put("ctrData", upgradeResponsePayload.getCtrData());

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Upgrade start step successfully completed",
                            "Upgrade start step was successfully completed",
                            "OK",
                            objectMap

                    );
                    stepLogger.writeDoneOK();
                }

                return model.getResultStatusObject();
            } else {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError(response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                    stepLogger.writeDoneFailed();
                }
                return null;
            }
        } catch (UnirestException exception) {
            if (stepLogger != null) {
                stepLogger.writeServerCallConnectionError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError(exception);
                stepLogger.writeDoneFailed();
            }
            return null;
        }
    }

}
