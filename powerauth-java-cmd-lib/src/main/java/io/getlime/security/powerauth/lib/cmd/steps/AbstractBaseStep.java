package io.getlime.security.powerauth.lib.cmd.steps;

import com.google.common.collect.ImmutableList;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
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
import lombok.Getter;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
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
    private final ImmutableList<PowerAuthVersion> supportedVersions;

    /**
     * Result status service
     */
    protected final ResultStatusService resultStatusService;

    /**
     * Step logger
     */
    protected final StepLoggerFactory stepLoggerFactory;

    private static final EciesFactory ECIES_FACTORY = new EciesFactory();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

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
     * Prepares ECIES encryptor and encrypts request data with sharedInfo1.
     * The encrypted request is then added to the request context of this step.
     *
     * @param stepContext       Context of this step
     * @param applicationSecret Application secret
     * @param eciesSharedInfo   Parameter sharedInfo1
     * @param data              Request data for the encryption
     * @param associatedData    Data associated with ECIES
     * @throws Exception when an error during encryption of the request data occurred
     */
    public void addEncryptedRequest(StepContext<M, R> stepContext, String applicationSecret, EciesSharedInfo1 eciesSharedInfo, byte[] data, byte[] associatedData) throws Exception {
        M model = stepContext.getModel();
        SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
        ResultStatusObject resultStatusObject = model.getResultStatus();

        EciesEncryptor encryptor;
        EciesParameters parameters;
        if (securityContext == null) {
            parameters = getRequestEciesParameters(stepContext.getModel().getVersion(), associatedData);
            encryptor = SecurityUtil.createEncryptorForActivationScope(applicationSecret, resultStatusObject, eciesSharedInfo, parameters);
            stepContext.setSecurityContext(
                    SimpleSecurityContext.builder()
                            .encryptor(encryptor)
                            .requestParameters(parameters)
                            .build()
            );
        } else {
            encryptor = securityContext.getEncryptor();
            parameters = securityContext.getRequestParameters();
        }

        final boolean useIv = model.getVersion().useIv();
        final boolean useTimestamp = model.getVersion().useTimestamp();

        final EciesPayload eciesPayload = encryptor.encrypt(data, parameters);
        final EciesEncryptedRequest encryptedRequest = SecurityUtil.createEncryptedRequest(eciesPayload);

        stepContext.getRequestContext().setRequestObject(encryptedRequest);
    }

    /**
     * Decrypts an object from a response
     *
     * @param stepContext       Step context
     * @param cls               Class type of the decrypted object
     * @param <T>               Class of the decrypted object
     * @param eciesScope        Scope of ECIES
     * @param associatedData    Data associated with ECIES
     * @return Decrypted object from the provided response
     * @throws Exception when an error during object decryption occurred
     */
    public <T> T decryptResponse(StepContext<?, EciesEncryptedResponse> stepContext, Class<T> cls, EciesScope eciesScope, byte[] associatedData) throws Exception {
        try {
            final PowerAuthVersion version = stepContext.getModel().getVersion();
            final SimpleSecurityContext securityContext = (SimpleSecurityContext) stepContext.getSecurityContext();
            EciesEncryptedResponse encryptedResponse = stepContext.getResponseContext().getResponseBodyObject();
            final byte[] transportMasterKeyBytes = Base64.getDecoder().decode(stepContext.getModel().getResultStatus().getTransportMasterKey());
            final byte[] nonceBytes = version.useDifferentIvForResponse() && encryptedResponse.getNonce() != null ? Base64.getDecoder().decode(encryptedResponse.getNonce()) : securityContext.getRequestParameters().getNonce();
            final Long timestamp = version.useTimestamp() ? encryptedResponse.getTimestamp() : null;
            EciesParameters eciesParameters = EciesParameters.builder()
                    .nonce(nonceBytes)
                    .timestamp(timestamp)
                    .build();
            String applicationSecret = (String) stepContext.getModel().toMap().get("APPLICATION_SECRET");
            byte[] ephemeralPublicKey = securityContext.getEncryptor().getEnvelopeKey().getEphemeralKeyPublic();
            EciesEncryptor encryptor = securityContext.getEncryptor();
            EciesDecryptor eciesDecryptor;
            if (eciesScope == EciesScope.ACTIVATION_SCOPE) {
                eciesDecryptor = ECIES_FACTORY.getEciesDecryptor(EciesScope.ACTIVATION_SCOPE,
                        encryptor.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes,
                        eciesParameters, ephemeralPublicKey);
            } else {
                eciesDecryptor = ECIES_FACTORY.getEciesDecryptor(EciesScope.APPLICATION_SCOPE,
                        encryptor.getEnvelopeKey(), applicationSecret.getBytes(StandardCharsets.UTF_8), null,
                        eciesParameters, ephemeralPublicKey);
            }

            byte[] decryptedBytes = SecurityUtil.decryptBytesFromResponse(eciesDecryptor, encryptedResponse, eciesParameters);

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
     * Create EciesParameters object for the new encrypted request.
     * @param version Protocol version.
     * @param associatedData Associated data to be a part of the request.
     * @return EciesParameters object.
     * @throws CryptoProviderException In case of random generator fails.
     */
    public EciesParameters getRequestEciesParameters(PowerAuthVersion version, byte[] associatedData) throws CryptoProviderException {
        final Long timestamp = version.useTimestamp() ? new Date().getTime() : null;
        final byte[] nonceBytes = version.useIv() ? KEY_GENERATOR.generateRandomBytes(16) : null;
        return EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();
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
