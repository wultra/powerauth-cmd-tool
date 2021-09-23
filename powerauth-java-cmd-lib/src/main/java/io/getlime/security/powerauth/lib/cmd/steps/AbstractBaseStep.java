package io.getlime.security.powerauth.lib.cmd.steps;

import com.google.common.collect.ImmutableList;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.DisabledStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.DryRunCapable;
import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import lombok.Getter;
import org.json.simple.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract step with common execution patterns and methods
 *
 * @param <M> Model data type
 * @param <R> Response type
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public abstract class AbstractBaseStep<M extends BaseStepData, R> implements BaseStep {

    /**
     * Corresponding PowerAuth step
     */
    @Getter
    private final PowerAuthStep step;

    /**
     * Supported versions of PowerAuth by this step
     */
    @Getter
    private final ImmutableList<PowerAuthVersion> supportedVersions;

    /**
     * Result status service
     */
    protected final ResultStatusService resultStatusService;

    /**
     * Step logger
     */
    protected StepLoggerFactory stepLoggerFactory;

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
        this.supportedVersions = ImmutableList.copyOf(supportedVersions);

        this.resultStatusService = resultStatusService;
        this.stepLoggerFactory = stepLoggerFactory;
    }

    /**
     * Prepares a context for this step execution
     *
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
        JSONObject jsonObject = execute(stepLogger, context);
        return ResultStatusObject.fromJsonObject(jsonObject);
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

        StepContext<M, R> stepContext = prepareStepContext(stepLogger, context);

        ResponseContext<R> responseContext;
        try {
            responseContext = callServer(stepContext);
            if (responseContext != null) {
                stepContext.setResponseContext(responseContext);
                processResponse(stepContext);
                stepLogger.writeDoneOK(getStep().id() + "-success");
            }
        } catch (Exception exception) {
            stepLogger.writeError(getStep().id() + "-error-generic", exception);
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }

        return stepContext.getModel().getResultStatusObject();
    }

    /**
     * Prepares ECIES encryptor and encrypts request data with sharedInfo1.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext       Context of this step
     * @param applicationSecret Application secret
     * @param eciesSharedInfo   Parameter sharedInfo1
     * @param data              Request data for the encyption
     * @throws Exception when an error during encryption of the request data occurred
     */
    public void addEncryptedRequest(StepContext<M, R> stepContext, String applicationSecret, EciesSharedInfo1 eciesSharedInfo, byte[] data) throws Exception {
        M model = stepContext.getModel();
        ResultStatusObject resultStatusObject = model.getResultStatus();

        EciesEncryptor encryptor = stepContext.getEncryptor();
        if (encryptor == null) {
            encryptor = SecurityUtil.createEncryptor(applicationSecret, resultStatusObject, eciesSharedInfo);
            stepContext.setEncryptor(encryptor);
        }

        final boolean useIv = model.getVersion().useIv();

        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(data, useIv);
        final EciesEncryptedRequest encryptedRequest = SecurityUtil.createEncryptedRequest(eciesCryptogram, useIv);

        stepContext.getRequestContext().setRequestObject(encryptedRequest);
    }

    /**
     * Decrypts an object from a response
     *
     * @param stepContext       Step context
     * @param cls               Class of the decrypted object
     * @return Decrypted object from the provided response
     * @throws Exception when an error during object decryption occurred
     */
    public <T> T decryptResponse(StepContext<?, EciesEncryptedResponse> stepContext, Class<T> cls) throws Exception {
        EciesEncryptor encryptor = stepContext.getEncryptor();
        EciesEncryptedResponse encryptedResponse = stepContext.getResponseContext().getResponseBodyObject();
        byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(encryptor, encryptedResponse);
        final T responsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, cls);

        stepContext.getStepLogger().writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                responsePayload
        );

        return responsePayload;
    }

    /**
     * Optional processing of the response data
     *
     * @param stepContext Step context
     * @throws Exception when an error during response processing occurred
     */
    public void processResponse(StepContext<M, R> stepContext) throws Exception { }

    /**
     * Builds a step context instance from a model and a request context
     *
     *
     * @param stepLogger
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
    protected void logDryRun(StepLogger stepLogger) { }

    /**
     * Calls the server and prepares response context with the response data
     */
    private @Nullable ResponseContext<R> callServer(StepContext<M, R> stepContext) throws Exception {
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

        stepContext.getStepLogger().writeServerCall(step.id() + "-request-sent", requestContext.getUri(), requestContext.getHttpMethod().name(), requestContext.getRequestObject(), headers);

        // In the case of a dry run the execution ends here
        if (model instanceof DryRunCapable && ((DryRunCapable) model).isDryRun()) {
            logDryRun(stepContext.getStepLogger());
            stepContext.getStepLogger().writeDoneOK(getStep().id() + "-success");
            return null;
        }

        RestClient restClient = RestClientFactory.getRestClient();
        if (restClient == null) {
            return null;
        }

        ResponseEntity<R> responseEntity;
        try {
            byte[] requestBytes = HttpUtil.toRequestBytes(requestContext.getRequestObject());

            // Call the right method with the REST client
            if (HttpMethod.GET.equals(requestContext.getHttpMethod())) {
                responseEntity = restClient.get(requestContext.getUri(), null, MapUtil.toMultiValueMap(headers), getResponseTypeReference());
            } else {
                responseEntity = restClient.post(requestContext.getUri(), requestBytes, null, MapUtil.toMultiValueMap(headers), getResponseTypeReference());
            }
        } catch (RestClientException ex) {
            stepContext.getStepLogger().writeServerCallError(step.id() + "-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
            stepContext.getStepLogger().writeDoneFailed(step.id() + "-failed");
            return null;
        }

        R responseBodyObject = Objects.requireNonNull(responseEntity.getBody());
        stepContext.getStepLogger().writeServerCallOK(step.id() + "-response-received", responseBodyObject, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

        return ResponseContext.<R>builder()
                .responseBodyObject(responseBodyObject)
                .responseEntity(responseEntity)
                .build();
    }

}
