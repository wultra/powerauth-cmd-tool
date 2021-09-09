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
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.TokenContext;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
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
 * Helper class with token creation logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class CreateTokenStep implements BaseStep {

    private static final KeyConvertor keyConvertor = new KeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private static final ObjectMapper mapper = RestClientConfiguration.defaultMapper();
    private static final EciesFactory eciesFactory = new EciesFactory();

    /**
     * Execute this step with given context
     *
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @SuppressWarnings("unchecked")
    @Override
    public ResultStatusObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {

        // Read properties from "context"
        CreateTokenStepModel model = new CreateTokenStepModel();
        model.fromMap(context);

        ResultStatusObject resultStatusObject = model.getResultStatusObject();

        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(resultStatusObject.getTransportMasterKey());
        final ECPublicKey serverPublicKey = (ECPublicKey) resultStatusObject.getServerPublicKeyObject();
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                transportMasterKeyBytes, EciesSharedInfo1.CREATE_TOKEN);

        TokenContext tokenContext = TokenContext.builder()
                .encryptor(encryptor)
                .model(model)
                .password(model.getPassword())
                .resultStatusObject(model.getResultStatusObject())
                .stepLogger(stepLogger)
                .build();

        EciesEncryptedRequest request = createRequest(tokenContext);

        final String uri = model.getUriString() + "/pa/v3/token/create";
        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        PowerAuthSignatureHttpHeader header = createSignatureHeader(request, tokenContext);
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
                stepLogger.writeServerCall("token-create-request-sent", uri, "POST", request, headers);
            }

            ResponseEntity<EciesEncryptedResponse> responseEntity;
            RestClient restClient = RestClientFactory.getRestClient();
            if (restClient == null) {
                return null;
            }
            ParameterizedTypeReference<EciesEncryptedResponse> typeReference = new ParameterizedTypeReference<EciesEncryptedResponse>() {
            };
            try {
                responseEntity = restClient.post(uri, requestBytes, null, MapUtil.toMultiValueMap(headers), typeReference);
            } catch (RestClientException ex) {
                if (stepLogger != null) {
                    stepLogger.writeServerCallError("token-create-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
                    stepLogger.writeDoneFailed("token-create-failed");
                }
                return null;
            }

            EciesEncryptedResponse encryptedResponse = Objects.requireNonNull(responseEntity.getBody());
            processResponse(encryptedResponse, responseEntity.getHeaders(), tokenContext);
            return resultStatusObject;
        } catch (Exception exception) {
            if (stepLogger != null) {
                stepLogger.writeError("token-create-error-generic", exception);
                stepLogger.writeDoneFailed("token-create-failed");
            }
            return null;
        }
    }

    public EciesEncryptedRequest createRequest(TokenContext tokenContext) throws Exception {
        StepLogger stepLogger = tokenContext.getStepLogger();

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "token-create-start",
                    "Token Create Started",
                    null,
                    "OK",
                    null
            );
        }

        // Prepare ECIES encryptor and encrypt request data with sharedInfo1 = /pa/token/create
        final boolean useIv = !"3.0" .equals(tokenContext.getModel().getVersion());
        final EciesCryptogram eciesCryptogram = tokenContext.getEncryptor().encryptRequest("{}" .getBytes(StandardCharsets.UTF_8), useIv);

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

        return request;
    }

    public PowerAuthSignatureHttpHeader createSignatureHeader(EciesEncryptedRequest request, TokenContext tokenContext) throws Exception {
        CreateTokenStepModel model = tokenContext.getModel();
        ResultStatusObject resultStatusObject = tokenContext.getResultStatusObject();

        byte[] signatureKnowledgeKeySalt = resultStatusObject.getSignatureKnowledgeKeySaltBytes();
        byte[] signatureKnowledgeKeyEncryptedBytes = resultStatusObject.getSignatureKnowledgeKeyEncryptedBytes();

        // Ask for the password to unlock knowledge factor key
        char[] password;
        if (tokenContext.getPassword() == null) {
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            password = tokenContext.getPassword().toCharArray();
        }

        // Get the signature keys
        SecretKey signaturePossessionKey = resultStatusObject.getSignaturePossessionKeyObject();
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(password, signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);

        // Generate nonce
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);

        final byte[] requestBytes = RestClientConfiguration.defaultMapper().writeValueAsBytes(request);

        // Compute the current PowerAuth signature for possession
        // and knowledge factor
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/token/create", nonceBytes, requestBytes) + "&" + model.getApplicationSecret();
        byte[] ctrData = CounterUtil.getCtrData(model, tokenContext.getStepLogger());
        PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(model.getVersion());
        String signatureValue = signature.signatureForData(signatureBaseString.getBytes(StandardCharsets.UTF_8), Arrays.asList(signaturePossessionKey, signatureKnowledgeKey), ctrData, signatureFormat);

        return new PowerAuthSignatureHttpHeader(resultStatusObject.getActivationId(), model.getApplicationKey(), signatureValue, model.getSignatureType().toString(), BaseEncoding.base64().encode(nonceBytes), model.getVersion());
    }

    public TokenResponsePayload processResponse(EciesEncryptedResponse encryptedResponse,
                                              HttpHeaders responseHeaders,
                                              TokenContext context) throws Exception {
        StepLogger stepLogger = context.getStepLogger();
        if (stepLogger != null) {
            stepLogger.writeServerCallOK("token-create-response-received", encryptedResponse, HttpUtil.flattenHttpHeaders(responseHeaders));
        }

        byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
        byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
        EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

        final byte[] decryptedBytes = context.getEncryptor().decryptResponse(eciesCryptogramResponse);

        final TokenResponsePayload tokenResponsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, TokenResponsePayload.class);

        Map<String, Object> objectMap = new HashMap<>();
        objectMap.put("tokenId", tokenResponsePayload.getTokenId());
        objectMap.put("tokenSecret", tokenResponsePayload.getTokenSecret());

        if (stepLogger != null) {
            stepLogger.writeItem(
                    "token-create-token-obtained",
                    "Token successfully obtained",
                    "Token was successfully generated and decrypted",
                    "OK",
                    objectMap

            );
            stepLogger.writeDoneOK("token-create-success");
        }

        return tokenResponsePayload;
    }

}
