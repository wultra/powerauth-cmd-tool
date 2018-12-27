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
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.JsonUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Encrypt step encrypts request data using ECIES encryption in application or activation scope.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class EncryptStep implements BaseStep {

    private static final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
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
                    "Encrypt Request Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare the encryption URI
        String uri = model.getUriString();

        // Read data which needs to be encrypted
        File dataFile = new File(model.getDataFileName());
        if (!dataFile.exists()) {
            if (stepLogger != null) {
                stepLogger.writeError("Encrypt Request Failed", "File not found: " + model.getDataFileName());
                stepLogger.writeDoneFailed();
            }
            return null;
        }

        Scanner scanner = new Scanner(dataFile);
        scanner.useDelimiter("\\Z");
        if (!scanner.hasNext()) {
            if (stepLogger != null) {
                stepLogger.writeError("Encrypt Request Failed", "File is empty: " + model.getDataFileName());
                stepLogger.writeDoneFailed();
            }
            return null;
        }
        String requestData = scanner.next();

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "Preparing Request Data",
                    "Following data will be encrypted",
                    "OK",
                    requestData
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
                final ECPublicKey serverPublicKey = (ECPublicKey) keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);
                final String activationId = JsonUtil.stringValue(model.getResultStatusObject(), "activationId");
                encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                        transportMasterKeyBytes, EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion());
                break;

            default:
                if (stepLogger != null) {
                    stepLogger.writeError("Encrypt Request Failed", "Unsupported encryption scope: " + model.getScope());
                    stepLogger.writeDoneFailed();
                }
                return null;
        }
        String httpEncryptionHeader = header.buildHttpHeader();

        // Prepare encrypted request
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(requestData.getBytes());
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        final String ephemeralPublicKeyBase64 = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        final String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        final String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        request.setEphemeralPublicKey(ephemeralPublicKeyBase64);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        if (stepLogger != null) {
            stepLogger.writeItem(
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

            HttpResponse response = Unirest.post(uri)
                    .headers(headers)
                    .body(requestBytes)
                    .asString();

            if (response.getStatus() == 200) {
                EciesEncryptedResponse encryptedResponse = RestClientConfiguration
                        .defaultMapper()
                        .readValue(response.getRawBody(), EciesEncryptedResponse.class);

                if (stepLogger != null) {
                    stepLogger.writeServerCallOK(encryptedResponse, HttpUtil.flattenHttpHeaders(response.getHeaders()));
                }

                byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
                byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
                EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

                final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

                String decryptedMessage = new String(decryptedBytes);
                model.getResultStatusObject().put("responseData", decryptedMessage);

                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Decrypted Response",
                            "Following data were decrypted",
                            "OK",
                            decryptedMessage
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
