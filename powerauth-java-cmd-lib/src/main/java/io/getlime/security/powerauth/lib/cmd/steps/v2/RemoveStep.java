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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.RemoveStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationRemoveResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class with activation remove logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak
 */
@Component(value = "removeStepV2")
public class RemoveStep extends AbstractBaseStepV2 {

    public static final ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>> RESPONSE_TYPE_REFERENCE =
            new ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>>() {
            };

    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();

    @Autowired
    public RemoveStep(StepLogger stepLogger) {
        super(PowerAuthStep.ACTIVATION_REMOVE, PowerAuthVersion.VERSION_2, stepLogger);
    }

    /**
     * Constructor for backward compatibility
     */
    public RemoveStep() {
        this(DEFAULT_STEP_LOGGER);
    }

    /**
     * Execute this step with given context
     *
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(Map<String, Object> context) throws Exception {

        // Read properties from "context"
        RemoveStepModel model = new RemoveStepModel();
        model.fromMap(context);

        // Prepare the activation URI
        String uri = model.getUriString() + "/pa/activation/remove";

        // Get data from status
        ResultStatusObject resultStatusObject = model.getResultStatus();
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

        // Compute the current PowerAuth signature for possession
        // and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/activation/remove", nonceBytes, null) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model.getResultStatus(), stepLogger);
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion().value());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureFormat);
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader(activationId, model.getApplicationKey(), signatureValue, PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE.toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion().value());
        String httpAuthorizationHeader = header.buildHttpHeader();

        // Increment the counter
        CounterUtil.incrementCounter(model);

        // Store the activation status (updated counter)
        String formatted = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(model.getResultStatus());
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

            stepLogger.writeServerCall("activation-remove-request-sent", uri, "POST", null, null, headers);

            ResponseEntity<ObjectResponse<ActivationRemoveResponse>> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>> typeReference = new ParameterizedTypeReference<ObjectResponse<ActivationRemoveResponse>>() {
            };
            try {
                responseEntity = restClient.post(uri, null, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                stepLogger.writeServerCallError("activation-remove-error-server-callactivation-remove-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                stepLogger.writeDoneFailed("activation-remove-failed");
                return null;
            }

            ObjectResponse<ActivationRemoveResponse> responseWrapper = Objects.requireNonNull(responseEntity.getBody());

            stepLogger.writeServerCallOK("activation-remove-response-received", responseWrapper, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

            Map<String, Object> objectMap = new HashMap<>();
            objectMap.put("activationId", activationId);

            stepLogger.writeItem(
                    "activation-remove-finished",
                    "Activation Removed",
                    "Activation was successfully removed from the server",
                    "OK",
                    objectMap

            );
            stepLogger.writeDoneOK("activation-remove-success");

            return model.getResultStatus();
        } catch (Exception exception) {
            stepLogger.writeError("activation-remove-error-generic", exception);
            stepLogger.writeDoneFailed("activation-remove-failed");
            return null;
        }
    }

}