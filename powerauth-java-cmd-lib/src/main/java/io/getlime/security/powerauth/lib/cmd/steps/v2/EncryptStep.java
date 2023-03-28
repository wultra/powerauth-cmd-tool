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
import io.getlime.security.powerauth.crypto.client.encryptor.ClientNonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil;
import io.getlime.security.powerauth.lib.cmd.util.MapUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Encrypt step encrypts request data using non-personalized end-to-end encryption.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "encryptStepV2")
public class EncryptStep extends AbstractBaseStepV2 {

    /**
     * Constructor
     * @param stepLogger Step logger
     */
    @Autowired
    public EncryptStep(StepLogger stepLogger) {
        super(PowerAuthStep.ENCRYPT, PowerAuthVersion.VERSION_2, stepLogger);
    }

    /**
     * Constructor for backward compatibility
     */
    public EncryptStep() {
        this(DEFAULT_STEP_LOGGER);
    }

    /**
     * Execute this step with given context.
     *
     * @param context Provided context.
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(Map<String, Object> context) throws Exception {

        // Read properties from "context"
        EncryptStepModel model = new EncryptStepModel();
        model.fromMap(context);

        // Prepare the encryption URI
        String uri = model.getUriString();

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            stepLogger.writeError("encrypt-error-data-file", "Encrypt Request Failed", "Request data for encryption was null.");
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }
        // Prepare the encryptor
        ClientNonPersonalizedEncryptor encryptor = new ClientNonPersonalizedEncryptor(Base64.getDecoder().decode(model.getApplicationKey()), model.getMasterPublicKey());

        // Encrypt the request data
        final NonPersonalizedEncryptedMessage encryptedMessage = encryptor.encrypt(requestDataBytes);
        if (encryptedMessage == null) {
            stepLogger.writeError("encrypt-error-missing-message", "Encryption failed", "Encrypted message is not available");
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }

        NonPersonalizedEncryptedPayloadModel encryptedRequestObject = new NonPersonalizedEncryptedPayloadModel();
        encryptedRequestObject.setAdHocIndex(Base64.getEncoder().encodeToString(encryptedMessage.getAdHocIndex()));
        encryptedRequestObject.setApplicationKey(Base64.getEncoder().encodeToString(encryptedMessage.getApplicationKey()));
        encryptedRequestObject.setEncryptedData(Base64.getEncoder().encodeToString(encryptedMessage.getEncryptedData()));
        encryptedRequestObject.setEphemeralPublicKey(Base64.getEncoder().encodeToString(encryptedMessage.getEphemeralPublicKey()));
        encryptedRequestObject.setMac(Base64.getEncoder().encodeToString(encryptedMessage.getMac()));
        encryptedRequestObject.setMacIndex(Base64.getEncoder().encodeToString(encryptedMessage.getMacIndex()));
        encryptedRequestObject.setNonce(Base64.getEncoder().encodeToString(encryptedMessage.getNonce()));
        encryptedRequestObject.setSessionIndex(Base64.getEncoder().encodeToString(encryptedMessage.getSessionIndex()));

        ObjectRequest<NonPersonalizedEncryptedPayloadModel> body = new ObjectRequest<>();
        body.setRequestObject(encryptedRequestObject);

        stepLogger.writeItem(
                "encrypt-request-encrypt",
                "Encrypting request data",
                "Following data is sent to intermediate server",
                "OK",
                body
        );

        try {

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            headers.putAll(model.getHeaders());

            stepLogger.writeServerCall("encrypt-request-sent", uri, "POST", body, null, headers);

            ResponseEntity<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>> typeReference = new ParameterizedTypeReference<ObjectResponse<NonPersonalizedEncryptedPayloadModel>>() {
            };
            try {
                responseEntity = restClient.post(uri, body, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                stepLogger.writeServerCallError("encrypt-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                stepLogger.writeDoneFailed("encrypt-failed");
                return null;
            }

            ObjectResponse<NonPersonalizedEncryptedPayloadModel> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            stepLogger.writeServerCallOK("encrypt-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

            // Decrypt the server response
            final NonPersonalizedEncryptedPayloadModel encryptedResponseObject = responseWrapper.getResponseObject();
            encryptedMessage.setApplicationKey(Base64.getDecoder().decode(encryptedResponseObject.getApplicationKey()));
            encryptedMessage.setAdHocIndex(Base64.getDecoder().decode(encryptedResponseObject.getAdHocIndex()));
            encryptedMessage.setEphemeralPublicKey(Base64.getDecoder().decode(encryptedResponseObject.getEphemeralPublicKey()));
            encryptedMessage.setEncryptedData(Base64.getDecoder().decode(encryptedResponseObject.getEncryptedData()));
            encryptedMessage.setMac(Base64.getDecoder().decode(encryptedResponseObject.getMac()));
            encryptedMessage.setMacIndex(Base64.getDecoder().decode(encryptedResponseObject.getMacIndex()));
            encryptedMessage.setNonce(Base64.getDecoder().decode(encryptedResponseObject.getNonce()));
            encryptedMessage.setSessionIndex(Base64.getDecoder().decode(encryptedResponseObject.getSessionIndex()));

            byte[] decryptedMessageBytes = encryptor.decrypt(encryptedMessage);
            if (decryptedMessageBytes == null) {
                stepLogger.writeError("encrypt-error-decrypt", "Decryption failed", "Decrypted message is not available");
                stepLogger.writeDoneFailed("encrypt-failed");
                return null;
            }

            String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
            model.getResultStatus().setResponseData(decryptedMessage);

            stepLogger.writeItem(
                    "encrypt-response-decrypt",
                    "Decrypted response",
                    "Following data were decrypted",
                    "OK",
                    decryptedMessage
            );
            stepLogger.writeDoneOK("encrypt-success");
            return model.getResultStatus();
        } catch (Exception exception) {
            stepLogger.writeError("encrypt-error-generic", exception);
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }
    }

}
