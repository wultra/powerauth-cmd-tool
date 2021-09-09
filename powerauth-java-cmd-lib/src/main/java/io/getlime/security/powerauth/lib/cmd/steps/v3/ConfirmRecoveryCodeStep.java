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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.ConfirmRecoveryCodeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v3.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class with confirm recovery logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ConfirmRecoveryCodeStep implements BaseStep {

    private static final KeyConvertor keyConversion = new KeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();
    private static final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Execute this step with given context
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        ConfirmRecoveryCodeStepModel model = new ConfirmRecoveryCodeStepModel();
        model.fromMap(context);

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "recovery-confirm",
                    "Confirm Recovery Code Started",
                    null,
                    "OK",
                    null
            );
        }

        ResultStatusObject resultStatusObject = model.getResultStatusObject();

        // Get data from status
        String activationId = resultStatusObject.getActivationId();
        byte[] signatureKnowledgeKeySalt = resultStatusObject.getSignatureKnowledgeKeySaltBytes();
        byte[] signatureKnowledgeKeyEncryptedBytes = resultStatusObject.getSignatureKnowledgeKeyEncryptedBytes();

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (model.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = model.getPassword().toCharArray();
        }

        // Get the signature keys
        SecretKey signaturePossessionKey = resultStatusObject.getSignaturePossessionKeyObject();
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        final String uri = model.getUriString() + "/pa/v3/recovery/confirm";

        // Prepare ECIES encryptor and encrypt request data with sharedInfo1 = /pa/token/create
        final boolean useIv = !"3.0".equals(model.getVersion());
        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final byte[] transportMasterKeyBytes = resultStatusObject.getTransportMasterKeyObject().getEncoded();
        final byte[] serverPublicKeyBytes = resultStatusObject.getServerPublicKeyObject().getEncoded();
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConversion.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, EciesSharedInfo1.CONFIRM_RECOVERY_CODE);

        // Prepare request
        final ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(model.getRecoveryCode());

        // Encrypt the request
        final byte[] requestBytesPayload = RestClientConfiguration.defaultMapper().writeValueAsBytes(confirmRequestPayload);
        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(requestBytesPayload, useIv);

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

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        // Compute the current PowerAuth signature for possession and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/recovery/confirm", nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureFormat);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), signatureValue, PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE.toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion());
        String httpAuthorizationHeader = header.buildHttpHeader();

        // Increment the counter
        CounterUtil.incrementCounter(model);

        // Store the activation status (updated counter)
        String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatusObject());
        try (FileWriter file = new FileWriter(model.getStatusFileName())) {
            file.write(formatted);
        }

        // Call the server with activation data
        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, httpAuthorizationHeader);
            headers.putAll(model.getHeaders());

            if (stepLogger != null) {
                stepLogger.writeServerCall("recovery-confirm-request-sent", uri, "POST", request, headers);
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
                    stepLogger.writeServerCallError("recovery-confirm-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("recovery-confirm-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponse = Objects.requireNonNull(responseEntity.getBody());

            if (stepLogger != null) {
                stepLogger.writeServerCallOK("recovery-confirm-response-received", encryptedResponse, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));
            }

            byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
            byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
            EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

            final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

            final ConfirmRecoveryResponsePayload confirmResponsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, ConfirmRecoveryResponsePayload.class);

            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("alreadyConfirmed", confirmResponsePayload.getAlreadyConfirmed());

            if (stepLogger != null) {
                stepLogger.writeItem(
                        "recovery-confirm-confirmation-done",
                        "Recovery Code Confirmed",
                        "Recovery code was successfully confirmed",
                        "OK",
                        objectMap

                );
                stepLogger.writeDoneOK("recovery-confirm-success");
            }

            return model.getResultStatusObject();
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("recovery-confirm-error-generic", exception);
                stepLogger.writeDoneFailed("recovery-confirm-failed");
            }
            return null;
        }
    }

}
