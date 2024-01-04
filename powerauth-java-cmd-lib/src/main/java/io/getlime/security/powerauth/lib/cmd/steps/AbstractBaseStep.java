/*
 * PowerAuth Command-line utility
 * Copyright 2023 Wultra s.r.o.
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

import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.DisabledStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.security.SimpleSecurityContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import jakarta.annotation.Nullable;
import lombok.Getter;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.*;

/**
 * Abstract step with common execution patterns and methods
 *
 * @param <M> Model data type
 * @param <R> Response type
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public abstract class AbstractBaseStep<M extends BaseStepData, R> implements BaseStep {

    private static final Logger logger = LoggerFactory.getLogger(AbstractBaseStep.class);

    /**
     * Corresponding PowerAuth step
     */
    @Getter
    private final PowerAuthStep step;

    /**
     * Supported versions of PowerAuth by this step
     */
    @Getter
    private final List<PowerAuthVersion> supportedVersions;

    /**
     * Result status service
     */
    protected final ResultStatusService resultStatusService;

    /**
     * Step logger
     */
    protected final StepLoggerFactory stepLoggerFactory;

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    /**
     * Constructor
     *
     * @param step                Corresponding PowerAuth step
     * @param supportedVersions   Supported versions of PowerAuth
     * @param resultStatusService Result status service
     * @param stepLoggerFactory   Step logger factory
     */
    public AbstractBaseStep(PowerAuthStep step,
                            List<PowerAuthVersion> supportedVersions,
                            ResultStatusService resultStatusService,
                            StepLoggerFactory stepLoggerFactory) {
        this.step = step;
        this.supportedVersions = List.copyOf(supportedVersions);

        this.resultStatusService = resultStatusService;
        this.stepLoggerFactory = stepLoggerFactory;
    }

    /**
     * Prepares a context for this step execution
     *
     * @param stepLogger Step logger
     * @param context Context data
     * @return Step context
     * @throws Exception when an error during context preparation occurred.
     */
    public abstract StepContext<M, R> prepareStepContext(StepLogger stepLogger, Map<String, Object> context) throws Exception;

    /**
     * @return Type reference of the response object
     */
    protected abstract ParameterizedTypeReference<R> getResponseTypeReference();

    /**
     * Executes this step with a given context
     *
     * @param context Provided context
     * @return Result status object, null in case of failure.
     * @throws Exception In case of any error.
     */
    @Override
    public ResultStatusObject execute(Map<String, Object> context) throws Exception {
        StepLogger stepLogger = stepLoggerFactory.createStepLogger();
        stepLogger.start();
        JSONObject jsonObject = execute(stepLogger, context);
        stepLogger.close();
        if (jsonObject == null) {
            return null;
        } else {
            return ResultStatusObject.fromJsonObject(jsonObject);
        }
    }

    /**
     * Execute this step with given logger and context objects.
     *
     * <p>Keeps backward compatibility with former approaches of step instantiation and execution</p>
     *
     * @param stepLogger Step logger.
     * @param context Context objects.
     * @return Result status object (with current activation status), null in case of failure.
     * @throws Exception In case of a failure.
     */
    public final JSONObject execute(StepLogger stepLogger, Map<String, Object> context) throws Exception {
        if (stepLogger == null) {
            stepLogger = DisabledStepLogger.INSTANCE;
        }
        stepLogger.writeItem(
                getStep().id() + "-start",
                getStep().description() + " Started",
                null,
                "OK",
                null
        );

        final StepContext<M, R> stepContext = prepareStepContext(stepLogger, context);
        if (stepContext == null) {
            return null;
        }

        try {
            ResponseContext<R> responseContext = callServer(stepContext);
            if (responseContext != null) {
                stepContext.setResponseContext(responseContext);
                processResponse(stepContext);
                stepLogger.writeDoneOK(getStep().id() + "-success");
            } else if (!isDryRun(stepContext.getModel())) {
                stepContext.getStepLogger().writeDoneFailed(getStep().id() + "-failed");
            }
        } catch (Exception exception) {
            stepLogger.writeError(getStep().id() + "-error-generic", exception);
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }

        return stepContext.getModel().getResultStatusObject();
    }

    /**
     * Prepares encryptor and encrypts request data with given encryptor.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext       Context of this step
     * @param applicationKey    Application key.
     * @param applicationSecret Application secret
     * @param encryptorId       Encryptor identifier
     * @param data              Request data for the encryption
     * @throws Exception when an error during encryption of the request data occurred
     */
    public void addEncryptedRequest(StepContext<M, R> stepContext, String applicationKey, String applicationSecret, EncryptorId encryptorId, byte[] data) throws Exception {
        M model = stepContext.getModel();
        final SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
        final ResultStatusObject resultStatusObject = model.getResultStatus();

        final ClientEncryptor encryptor;
        if (securityContext == null) {
            final byte[] transportMasterKeyBytes = Base64.getDecoder().decode(resultStatusObject.getTransportMasterKey());
            final EncryptorParameters encryptorParameters = new EncryptorParameters(model.getVersion().value(), applicationKey, resultStatusObject.getActivationId());
            final ClientEncryptorSecrets encryptorSecrets = new ClientEncryptorSecrets(resultStatusObject.getServerPublicKeyObject(), applicationSecret, transportMasterKeyBytes);
            encryptor = ENCRYPTOR_FACTORY.getClientEncryptor(encryptorId, encryptorParameters, encryptorSecrets);
            stepContext.setSecurityContext(SimpleSecurityContext.builder()
                            .encryptor(encryptor)
                            .build());
        } else {
            encryptor = securityContext.getEncryptor();
        }
        addEncryptedRequest(stepContext, encryptor, data);
    }

    /**
     * Encrypts request data with given encryptor.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext       Context of this step
     * @param encryptor         Encryptor to use
     * @param data              Request data for the encryption
     * @throws Exception when an error during encryption of the request data occurred
     */
    public void addEncryptedRequest(StepContext<M, R> stepContext, ClientEncryptor encryptor, byte[] data) throws Exception {
        M model = stepContext.getModel();
        SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
        if (securityContext == null) {
            stepContext.setSecurityContext(
                    SimpleSecurityContext.builder()
                            .encryptor(encryptor)
                            .build()
            );
        } else if (securityContext.getEncryptor() != encryptor) {
            throw new Exception("Different encryptor is already set to security context");
        }

        final EncryptedRequest encryptedRequest = encryptor.encryptRequest(data);
        final EciesEncryptedRequest requestObject = SecurityUtil.createEncryptedRequest(encryptedRequest);
        stepContext.getRequestContext().setRequestObject(requestObject);
    }

    /**
     * Decrypts an object from a response
     *
     * @param stepContext       Step context
     * @param cls               Class type of the decrypted object
     * @param <T>               Class of the decrypted object
     * @return Decrypted object from the provided response
     */
    public <T> T decryptResponse(StepContext<?, EciesEncryptedResponse> stepContext, Class<T> cls) {
        try {
            final SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
            final EciesEncryptedResponse encryptedResponse = stepContext.getResponseContext().getResponseBodyObject();
            final byte[] decryptedBytes = securityContext.getEncryptor().decryptResponse(new EncryptedResponse(
                    encryptedResponse.getEncryptedData(),
                    encryptedResponse.getMac(),
                    encryptedResponse.getNonce(),
                    encryptedResponse.getTimestamp()
            ));
            final T responsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, cls);
            stepContext.getResponseContext().setResponsePayloadDecrypted(responsePayload);

            stepContext.getStepLogger().writeItem(
                    getStep().id() + "-response-decrypt",
                    "Decrypted Response",
                    "Following data were decrypted",
                    "OK",
                    responsePayload
            );

            return responsePayload;
        } catch (Exception ex) {
            logger.debug(ex.getMessage(), ex);
            return null;
        }
    }

    /**
     * Optional processing of the response data
     *
     * @param stepContext Step context
     * @throws Exception when an error during response processing occurred
     */
    public void processResponse(StepContext<M, R> stepContext) throws Exception { }

    /**
     * Processing of the response data bytes
     *
     * @param stepContext Step context
     * @param responseBody Response body bytes
     * @param responseObjectClass Response object class
     * @throws Exception when an error during response processing occurred
     */
    public final void processResponse(StepContext<M, R> stepContext, byte[] responseBody, Class<R> responseObjectClass) throws Exception {
        R responseBodyObject = HttpUtil.fromBytes(responseBody, responseObjectClass);
        ResponseEntity<R> responseEntity = ResponseEntity.of(Optional.of(responseBodyObject));
        addResponseContext(stepContext, responseEntity);
        processResponse(stepContext);
    }

    /**
     * Builds a step context instance from a model and a request context
     *
     * @param stepLogger     Step logger
     * @param model          Data model
     * @param requestContext Request context
     * @return Step context instance
     */
    protected final StepContext<M, R> buildStepContext(StepLogger stepLogger, M model, RequestContext requestContext) {
        StepContext<M, R> context = new StepContext<>();
        context.setModel(model);
        context.setRequestContext(requestContext);
        context.setStep(getStep());
        context.setStepLogger(stepLogger);
        return context;
    }

    /**
     * Increments the counter (the signature already used hash based counter)
     * @param model Model
     * @param <RS> Type of the model with result status
     * @throws Exception when an error during saving the model occurred
     */
    protected <RS extends ResultStatusChangeable> void incrementCounter(RS model) throws Exception {
        CounterUtil.incrementCounter(model);
        resultStatusService.save(model);
    }

    /**
     * Optional way to log special messages when in a dry run (no real service call)
     *
     * @param stepLogger Step logger
     */
    protected void logDryRun(StepLogger stepLogger) {
        stepLogger.writeItem(
                getStep().id() + "-dry-run",
                "Dry run",
                "The request was just dry-run, no external service call",
                "OK",
                null
        );
    }

    /**
     * Calls the server and prepares response context with the response data
     */
    private @Nullable ResponseContext<R> callServer(StepContext<M, R> stepContext) throws Exception {
        if (stepContext == null) {
            return null;
        }

        final ParameterizedTypeReference<R> responseTypeReference = getResponseTypeReference();
        if (responseTypeReference == null) {
            return null;
        }

        M model = stepContext.getModel();
        RequestContext requestContext = stepContext.getRequestContext();

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        // put all headers from request context (includes e.g. authorization header)
        headers.putAll(requestContext.getHttpHeaders());
        if (model.getHeaders() != null && !model.getHeaders().isEmpty()) {
            headers.putAll(model.getHeaders());
        }

        byte[] requestBytes = HttpUtil.toRequestBytes(requestContext.getRequestObject());

        stepContext.getStepLogger().writeServerCall(step.id() + "-request-sent", requestContext.getUri(), requestContext.getHttpMethod().name(), requestContext.getRequestObject(), requestBytes, headers);

        // In the case of a dry run the execution ends here
        if (isDryRun(model)) {
            logDryRun(stepContext.getStepLogger());
            stepContext.getStepLogger().writeDoneOK(getStep().id() + "-success");
            return null;
        }

        RestClient restClient = RestClientFactory.getRestClient();
        if (restClient == null) {
            stepContext.getStepLogger().writeError(step.id() + "-error-rest-client", "Unable to prepare a REST client");
            return null;
        }

        ResponseEntity<R> responseEntity;
        try {
            // Call the right method with the REST client
            if (HttpMethod.GET.equals(requestContext.getHttpMethod())) {
                responseEntity = restClient.get(requestContext.getUri(), null, MapUtil.toMultiValueMap(headers), responseTypeReference);
            } else {
                responseEntity = restClient.post(requestContext.getUri(), requestBytes, null, MapUtil.toMultiValueMap(headers), responseTypeReference);
            }
        } catch (RestClientException ex) {
            stepContext.getStepLogger().writeServerCallError(step.id() + "-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
            return null;
        }

        return addResponseContext(stepContext, responseEntity);
    }

    private ResponseContext<R> addResponseContext(StepContext<M,R> stepContext, ResponseEntity<R> responseEntity) {
        R responseBodyObject = Objects.requireNonNull(responseEntity.getBody());
        stepContext.getStepLogger().writeServerCallOK(step.id() + "-response-received", responseBodyObject, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

        ResponseContext<R> responseContext = ResponseContext.<R>builder()
                .responseBodyObject(responseBodyObject)
                .responseEntity(responseEntity)
                .build();

        stepContext.setResponseContext(responseContext);
        return responseContext;
    }

    private boolean isDryRun(M model) {
        return model instanceof DryRunCapable && ((DryRunCapable) model).isDryRun();
    }

}
