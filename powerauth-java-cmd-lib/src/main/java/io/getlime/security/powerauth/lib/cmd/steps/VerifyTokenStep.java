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
package io.getlime.security.powerauth.lib.cmd.steps;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.json.simple.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Step for the token validation activity.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class VerifyTokenStep implements BaseStep {

    @Override
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.fromMap(context);

        // Initiate the step sequence
        logTokenVerificationStart(model.getTokenId(), model.getTokenSecret(), stepLogger);

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
                new String(tokenTimestamp, StandardCharsets.UTF_8),
                model.getVersion()
        ).buildHttpHeader();

        if (model.getHttpMethod() == null) {
            if (stepLogger != null) {
                stepLogger.writeError("token-validate-error-http-method", "HTTP method not specified", "Specify HTTP method to use for sending request");
                stepLogger.writeDoneFailed("token-validate-failed");
            }
            return null;
        }

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
                            "token-validate-warning-empty-data",
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
                stepLogger.writeServerCall("token-validate-request-sent", model.getUriString(), model.getHttpMethod().toUpperCase(), dataFileBytes != null ? new String(dataFileBytes, StandardCharsets.UTF_8) : null, headers);
            }

            if (!model.isDryRun()) {
                final boolean success = executeRequest(model.getHttpMethod().toUpperCase(), headers, model.getUriString(), dataFileBytes, stepLogger);
                if (success) {
                    return model.getResultStatusObject();
                } else {
                    return null;
                }
            } else {
                logTokenValueComputed(stepLogger);
                return model.getResultStatusObject();
            }
        } catch (UnirestException exception) {
            logException("token-validate-error-server-call", exception, stepLogger);
            return null;
        } catch (Exception exception) {
            logException("token-validate-generic", exception, stepLogger);
            return null;
        }

    }

    /**
     * Log the initiation of the token verification steps.
     * @param tokenId Token ID.
     * @param tokenSecret Token secret.
     * @param stepLogger Instance of logger.
     */
    private void logTokenVerificationStart(String tokenId, String tokenSecret, StepLogger stepLogger) {
        if (stepLogger != null) {
            Map<String, String> map = new HashMap<>();
            map.put("TOKEN_ID", tokenId);
            map.put("TOKEN_SECRET", tokenSecret);
            stepLogger.writeItem(
                    "token-validate-start",
                    "Token Digest Validation Started",
                    null,
                    "OK",
                    map
            );
        }
    }

    /**
     * Log exception.
     * @param id ID to be used for the exception log.
     * @param exception Exception to be logged.
     * @param stepLogger Logger instance.
     */
    private void logException(String id, Exception exception, StepLogger stepLogger) {
        if (stepLogger != null) {
            stepLogger.writeError(id, exception);
            stepLogger.writeDoneFailed("token-validate-failed");
        }
    }

    /**
     * Log information about the token value successfully computed.
     * @param stepLogger Instance of the logger.
     */
    private void logTokenValueComputed(StepLogger stepLogger) {
        if (stepLogger != null) {

            // Print the results
            stepLogger.writeItem(
                    "token-validate-token-computed",
                    "Token value computed",
                    "Token value header was computed successfully",
                    "OK",
                    null

            );

            stepLogger.writeDoneOK("token-validate-success");
        }
    }

    /**
     * Execute request for the token validation result.
     * @param method HTTP method.
     * @param headers HTTP headers.
     * @param uri Full URI for the token verification.
     * @param data HTTP request body.
     * @param stepLogger Logger instance.
     * @return True in case the request is successful, false otherwise.
     * @throws JsonProcessingException In case parsing the response to JSON format fails.
     */
    private boolean executeRequest(String method, Map<String, String> headers, String uri, byte[] data, StepLogger stepLogger) throws JsonProcessingException {
        HttpResponse<String> response;
        if ("GET".equals(method)) {
            response = Unirest.get(uri)
                    .headers(headers)
                    .asString();
        } else {
            response = Unirest.post(uri)
                    .headers(headers)
                    .body(data)
                    .asString();
        }

        if (response.getStatus() == 200) {
            TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
            };
            Map<String, Object> responseWrapper = RestClientConfiguration
                    .defaultMapper()
                    .readValue(response.getBody(), typeReference);

            if (stepLogger != null) {
                stepLogger.writeServerCallOK("token-validate-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(response.getHeaders()));

                // Print the results
                stepLogger.writeItem(
                        "token-validate-digest-verified",
                        "Token digest verified",
                        "Token based authentication was successful",
                        "OK",
                        null

                );

                stepLogger.writeDoneOK("token-validate-success");
            }
            return true;
        } else {
            if (stepLogger != null) {
                stepLogger.writeServerCallError("token-validate-error-server-call", response.getStatus(), response.getBody(), HttpUtil.flattenHttpHeaders(response.getHeaders()));
                stepLogger.writeDoneFailed("token-validate-failed");
            }
            return false;
        }
    }

}
