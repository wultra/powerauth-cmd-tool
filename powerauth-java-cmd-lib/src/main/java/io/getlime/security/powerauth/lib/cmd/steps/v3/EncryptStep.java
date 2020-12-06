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
package io.getlime.security.powerauth.lib.cmd.steps.v3;

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
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Encrypt step encrypts request data using ECIES encryption in application or activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class EncryptStep implements BaseStep {

    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Execute this step with given context.
     * @param stepLogger Step logger.
     * @param context Provided context.
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    public JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        EncryptStepModel model = new EncryptStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "encrypt-started",
                    "Encrypt Request Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the encryption URI
        String uri = model.getUriString();

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            if (stepLogger != null) {
                stepLogger.writeError("encrypt-error-file", "Encrypt Request Failed", "Request data for encryption was null.");
                stepLogger.writeDoneFailed("encrypt-failed");
            }
            return null;
        }

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "encrypt-request-encrypt",
                    "Preparing Request Data",
                    "Following data will be encrypted",
                    "OK",
                    requestDataBytes
            );
        }

        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final EciesEncryptor encryptor;
        // Prepare the encryption header
        final PowerAuthEncryptionHttpHeader header;
        switch (model.getScope()) {
            case "application":
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/application
                encryptor = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(),
                        applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), model.getVersion());
                break;

            case "activation":
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/activation
                final byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "transportMasterKey"));
                final byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(model.getResultStatusObject(), "serverPublicKey"));
                final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
                final String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");
                encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                        transportMasterKeyBytes, EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion());
                break;

            default:
                if (stepLogger != null) {
                    stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported encryption scope: " + model.getScope());
                    stepLogger.writeDoneFailed("encrypt-failed");
                }
                return null;
        }
        String httpEncryptionHeader = header.buildHttpHeader();

        // Prepare encrypted request
        final boolean useIv = !"3.0".equals(model.getVersion());
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(requestDataBytes, useIv);
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        final String nonce = useIv ? BaseEncoding.base64().encode(eciesCryptogram.getNonce()) : null;
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "encrypt-request-encrypt",
                    "Encrypting Request Data",
                    "Following data is sent to intermediate server",
                    "OK",
                    request
            );
        }

        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthEncryptionHttpHeader.HEADER_NAME, httpEncryptionHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall("encrypt-request-sent", uri, "POST", request, headers);
            }

            ResponseEntity<EciesEncryptedResponse> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            ParameterizedTypeReference<EciesEncryptedResponse> typeReference = new ParameterizedTypeReference<EciesEncryptedResponse>() {};
            try {
                responseEntity = restClient.post(uri, requestBytes, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("encrypt-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("encrypt-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponse = Objects.requireNonNull(responseEntity.getBody());

            if (stepLogger != null) {
                stepLogger.writeServerCallOK("encrypt-response-received", encryptedResponse, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
            byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
            EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

            final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            model.getResultStatusObject().put("responseData", decryptedMessage);

            if (stepLogger != null) {
                stepLogger.writeItem(
                        "encrypt-response-decrypt",
                        "Decrypted Response",
                        "Following data were decrypted",
                        "OK",
                        decryptedMessage
                );
                stepLogger.writeDoneOK("encrypt-success");
            }
            return model.getResultStatusObject();
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("encrypt-error-generic", exception);
                stepLogger.writeDoneFailed("encrypt-failed");
            }
            return null;
        }
    }

}
