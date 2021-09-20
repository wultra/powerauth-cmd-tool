package io.getlime.security.powerauth.lib.cmd.steps;

import com.google.common.collect.ImmutableList;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.DisabledStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.ResponseContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.EncryptionHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.SignatureHeaderData;
import io.getlime.security.powerauth.lib.cmd.steps.model.data.TokenHeaderData;
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
    protected StepLogger stepLogger;

    /**
     * Constructor
     *
     * @param step                Corresponding PowerAuth step
     * @param supportedVersions   Supported versions of PowerAuth
     * @param resultStatusService Result status service
     * @param stepLogger          Step logger
     */
    public AbstractBaseStep(PowerAuthStep step,
                            List<PowerAuthVersion> supportedVersions,
                            ResultStatusService resultStatusService,
                            StepLogger stepLogger) {
        this.step = step;
        this.supportedVersions = ImmutableList.copyOf(supportedVersions);

        this.resultStatusService = resultStatusService;
        this.stepLogger = stepLogger;
    }

    /**
     * Prepares a context for this step execution
     *
     * @param context Context data
     * @return Step context
     * @throws Exception when an error during context preparation occurred.
     */
    public abstract StepContext<M, R> prepareStepContext(Map<String, Object> context) throws Exception;

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
        stepLogger.writeItem(
                getStep().id() + "-start",
                getStep().description() + " Started",
                null,
                "OK",
                null
        );

        StepContext<M, R> stepContext = prepareStepContext(context);

        // TODO is this necessary?
        M model = stepContext.getModel();
        if (model instanceof ResultStatusChangeable) {
            // Store the activation status (typically with updated counter)
            resultStatusService.save((ResultStatusChangeable) model);
        }

        ResponseContext<R> response;
        try {
            response = callServer(stepContext);
            if (response != null) {
                stepContext.setResponseContext(response);
                processResponse(stepContext);
                stepLogger.writeDoneOK(getStep().id() + "-success");
            }
        } catch (Exception exception) {
            stepLogger.writeError(getStep().id() + "-error-generic", exception);
            stepLogger.writeDoneFailed(getStep().id() + "-failed");
            return null;
        }
        return model.getResultStatus();
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
        this.stepLogger = stepLogger != null ? stepLogger : new DisabledStepLogger();
        ResultStatusObject resultStatusObject = execute(context);
        return resultStatusObject != null ? resultStatusObject.toJsonObject() : null;
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

        EciesEncryptor encryptor = SecurityUtil.createEncryptor(applicationSecret, resultStatusObject, eciesSharedInfo);
        stepContext.setEncryptor(encryptor);

        final boolean useIv = model.getVersion().useIv();

        final EciesCryptogram eciesCryptogram = encryptor.encryptRequest(data, useIv);
        final EciesEncryptedRequest encryptedRequest = SecurityUtil.createEncryptedRequest(eciesCryptogram, useIv);

        stepContext.getRequestContext().setRequestObject(encryptedRequest);
    }

    /**
     * Decrypts an object from a response
     *
     * @param encryptor         Encryptor instance
     * @param encryptedResponse Encrypted response
     * @param cls               Class of the decrypted object
     * @return Decrypted object from the provided response
     * @throws Exception when an error during object decryption occurred
     */
    public <T> T decryptResponse(EciesEncryptor encryptor, EciesEncryptedResponse encryptedResponse, Class<T> cls) throws Exception {
        byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(encryptor, encryptedResponse);
        final T responsePayload = RestClientConfiguration.defaultMapper().readValue(decryptedBytes, cls);

        stepLogger.writeItem(
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
    public void processResponse(StepContext<M, R> stepContext) throws Exception {
    }

    /**
     * Builds a step context instance from a model and a request context
     *
     * @param model          Data model
     * @param requestContext Request context
     * @return Step context instance
     */
    protected final StepContext<M, R> buildStepContext(M model, RequestContext requestContext) {
        StepContext<M, R> context = new StepContext<>();
        context.setModel(model);
        context.setRequestContext(requestContext);
        context.setStep(getStep());
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
     */
    protected void logDryRun() { }

    /**
     * Calls the server and prepares response context with the response data
     */
    private @Nullable
    ResponseContext<R> callServer(StepContext<M, R> stepContext) throws Exception {
        M model = stepContext.getModel();
        RequestContext requestContext = stepContext.getRequestContext();

        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        if (model instanceof EncryptionHeaderData) {
            headers.put(PowerAuthEncryptionHttpHeader.HEADER_NAME, requestContext.getAuthorizationHeader());
        } else if (model instanceof SignatureHeaderData) {
            headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, requestContext.getAuthorizationHeader());
        } else if (model instanceof TokenHeaderData) {
            headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, requestContext.getAuthorizationHeader());
        }

        if (model.getHeaders() != null && !model.getHeaders().isEmpty()) {
            headers.putAll(model.getHeaders());
        }

        stepLogger.writeServerCall(step.id() + "-request-sent", requestContext.getUri(), "POST", requestContext.getRequestObject(), headers);

        // In the case of a dry run the execution ends here
        if (model instanceof DryRunCapable && ((DryRunCapable) model).isDryRun()) {
            logDryRun();
            stepLogger.writeDoneOK(getStep().id() + "-success");
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
            if ("GET".equals(requestContext.getHttpMethod())) {
                responseEntity = restClient.get(requestContext.getUri(), null, MapUtil.toMultiValueMap(headers), getResponseTypeReference());
            } else {
                responseEntity = restClient.post(requestContext.getUri(), requestBytes, null, MapUtil.toMultiValueMap(headers), getResponseTypeReference());
            }
        } catch (RestClientException ex) {
            stepLogger.writeServerCallError(step.id() + "-error-server-call", ex.getStatusCode().value(), ex.getResponse(), HttpUtil.flattenHttpHeaders(ex.getResponseHeaders()));
            stepLogger.writeDoneFailed(step.id() + "-failed");
            return null;
        }

        R responseBodyObject = Objects.requireNonNull(responseEntity.getBody());
        stepLogger.writeServerCallOK(step.id() + "-response-received", responseBodyObject, HttpUtil.flattenHttpHeaders(responseEntity.getHeaders()));

        return ResponseContext.<R>builder()
                .responseBodyObject(responseBodyObject)
                .responseEntity(responseEntity)
                .build();
    }

}
