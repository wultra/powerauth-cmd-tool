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
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.JsonUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Step for committing upgrade to PowerAuth protocol version 3.0.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CommitUpgradeStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    /**
     * Execute this step with given context.
     * @param context Provided context.
     * @return Result status object, null in case of failure.
     */
    @SuppressWarnings("unchecked")
    @Override
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) {

        // Read properties from "context"
        StartUpgradeStepModel model = new StartUpgradeStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Upgrade Commit Started",
                    null,
                    "OK",
                    null
            );
        }

        final String uri = model.getUriString() + "/pa/v3/upgrade/commit";
        final String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");

        // Get the signature key (possession factor)
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "signaturePossessionKey"));
        final SecretKey signaturePossessionKey = keyConversion.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);

        // Generate nonce
        byte[] pa_nonce = keyGenerator.generateRandomBytes(16);

        // Prepare request data
        final String request = "{}";
        byte[] requestBytes = request.getBytes(StandardCharsets.UTF_8);

        // Make sure hash based counter is used for calculating the signature, in case of an error the version change is not saved
        model.getResultStatusObject().put("version", 3L);

        try {
            // Compute PowerAuth signature for possession factor
            String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/upgrade/commit", pa_nonce, requestBytes) + "&" + model.getApplicationSecret();
            byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
            PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
            String pa_signature = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), Collections.singletonList(signaturePossessionKey), ctrData, signatureFormat);
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), pa_signature, PowerAuthSignatureTypes.POSSESSION.toString(), BaseEncoding.base64().encode(pa_nonce), model.getVersion());
            String httpAuthorizationHeader = header.buildHttpHeader();

            // Commit upgrade
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, httpAuthorizationHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall(uri, "POST", request, headers);
            }

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(requestBytes)
                    .asString();

            if (response.getStatus() == 200) {
                Response commitResponse = mapper.readValue(response.getRawBody(), Response.class);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(commitResponse, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                // Increment the counter (the signature already used hash based counter)
                CounterUtil.incrementCounter(model);

                // Store the result status object into file
                String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
                try (FileWriter file = new FileWriter(model.getStatusFileName())) {
                    file.write(formatted);
                }

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Upgrade commit successfully completed",
                            "Upgrade commit was successfully completed",
                            "OK",
                            null

                    );
                    stepLogger.writeDoneOK();
                }

                return model.getResultStatusObject();
            } else {
                // Revert upgrade to version 3 because signature failed. The status file was not changed, so no need to save it.
                model.getResultStatusObject().put("version", 2L);

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
