/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import org.json.simple.JSONObject;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Step for the token validation activity.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class VerifyTokenStep implements BaseStep {

    @Override
    public JSONObject execute(JsonStepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            Map<String, String> map = new HashMap<>();
            map.put("TOKEN_ID", model.getTokenId());
            map.put("TOKEN_SECRET", model.getTokenSecret());
            stepLogger.writeItem(
                    "Token Digest Validation Started",
                    null,
                    "OK",
                    map
            );
        }

        String tokenId = model.getTokenId();
        byte[] tokenSecret = BaseEncoding.base64().decode(model.getTokenSecret());

        ClientTokenGenerator tokenGenerator = new ClientTokenGenerator();
        final byte[] tokenNonce = tokenGenerator.generateTokenNonce();
        final byte[] tokenTimestamp = tokenGenerator.generateTokenTimestamp();
        final byte[] tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, tokenSecret);

        String tokenHeader = new PowerAuthTokenHttpHeader(
                tokenId,
                BaseEncoding.base64().encode(tokenDigest),
                BaseEncoding.base64().encode(tokenNonce),
                new String(tokenTimestamp, "UTF-8"),
                "2.1"
        ).buildHttpHeader();

        // Construct the signature base string data part based on HTTP method (GET requires different code).
        byte[] dataFileBytes = null;
        if (!"GET".equals(model.getHttpMethod().toUpperCase())) {
            // Read data input file
            if (model.getDataFileName() != null && Files.exists(Paths.get(model.getDataFileName()))) {
                dataFileBytes = Files.readAllBytes(Paths.get(model.getDataFileName()));
            } else {
                dataFileBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Empty data",
                            "Data file was not found, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        }

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall(model.getUriString(), model.getHttpMethod().toUpperCase(), dataFileBytes != null ? new String(dataFileBytes, "UTF-8") : null, headers);
            }

            HttpResponse response;
            if ("GET".equals(model.getHttpMethod().toUpperCase())) {
                response = Unirest.get(model.getUriString())
                        .headers(headers)
                        .asString();
            } else {
                response = Unirest.post(model.getUriString())
                        .headers(headers)
                        .body(dataFileBytes)
                        .asString();
            }

            if (response.getStatus() == 200) {
                TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {};
                Map<String, Object> responseWrapper = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), typeReference);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

                    // Print the results
                    stepLogger.writeItem(
                            "Token digest verified",
                            "Token based authentication was successful",
                            "OK",
                            null

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
