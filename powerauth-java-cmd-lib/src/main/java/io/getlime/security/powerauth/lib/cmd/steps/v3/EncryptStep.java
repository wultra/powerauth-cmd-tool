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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * Encrypt step encrypts request data using ECIES encryption in application or activation scope.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component(value = "encryptStepV3")
public class EncryptStep extends AbstractBaseStep<EncryptStepModel, EciesEncryptedResponse> {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final EciesFactory ECIES_FACTORY = new EciesFactory();

    @Autowired
    public EncryptStep(ResultStatusService resultStatusService, StepLogger stepLogger) {
        super(PowerAuthStep.ENCRYPT, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<EncryptStepModel, EciesEncryptedResponse> prepareStepContext(Map<String, Object> context) throws Exception {
        EncryptStepModel model = new EncryptStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.<EncryptStepModel>builder()
                .uri(model.getUriString())
                .build();

        StepContext<EncryptStepModel, EciesEncryptedResponse> stepContext = buildStepContext(model, requestContext);

        // Read data which needs to be encrypted
        final byte[] requestDataBytes = model.getData();
        if (requestDataBytes == null) {
            stepLogger.writeError("encrypt-error-file", "Encrypt Request Failed", "Request data for encryption was null.");
            stepLogger.writeDoneFailed("encrypt-failed");
            return null;
        }

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Preparing Request Data",
                "Following data will be encrypted",
                "OK",
                requestDataBytes
        );

        final byte[] applicationSecret = model.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        final EciesEncryptor encryptor;

        // Prepare the encryption header
        final PowerAuthEncryptionHttpHeader header;
        switch (model.getScope()) {
            case "application":
                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/application
                encryptor = ECIES_FACTORY.getEciesEncryptorForApplication((ECPublicKey) model.getMasterPublicKey(),
                        applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), model.getVersion().value());
                break;

            case "activation":
                ResultStatusObject resultStatusObject = model.getResultStatusObject();

                // Prepare ECIES encryptor with sharedInfo1 = /pa/generic/activation
                final byte[] transportMasterKeyBytes = resultStatusObject.getTransportMasterKeyObject().getEncoded();
                final byte[] serverPublicKeyBytes = resultStatusObject.getServerPublicKeyObject().getEncoded();
                final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
                final String activationId = resultStatusObject.getActivationId();
                encryptor = ECIES_FACTORY.getEciesEncryptorForActivation(serverPublicKey, applicationSecret,
                        transportMasterKeyBytes, EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC);
                header = new PowerAuthEncryptionHttpHeader(model.getApplicationKey(), activationId, model.getVersion().value());
                break;

            default:
                stepLogger.writeError("encrypt-error-scope", "Encrypt Request Failed", "Unsupported encryption scope: " + model.getScope());
                stepLogger.writeDoneFailed("encrypt-failed");
                return null;
        }

        stepContext.setEncryptor(encryptor);
        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.APPLICATION_SCOPE_GENERIC, requestDataBytes);
        requestContext.setAuthorizationHeader(header.buildHttpHeader());

        stepLogger.writeItem(
                getStep().id() + "-request-encrypt",
                "Encrypting Request Data",
                "Following data is sent to intermediate server",
                "OK",
                requestContext.getRequestObject()
        );

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<EncryptStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        EncryptStepModel model = stepContext.getModel();
        EciesEncryptor encryptor = stepContext.getEncryptor();

        EciesEncryptedResponse encryptedResponse = stepContext.getResponseContext().getResponseBodyObject();

        byte[] macResponse = BaseEncoding.base64().decode(encryptedResponse.getMac());
        byte[] encryptedDataResponse = BaseEncoding.base64().decode(encryptedResponse.getEncryptedData());
        EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);

        final byte[] decryptedBytes = encryptor.decryptResponse(eciesCryptogramResponse);

        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        model.getResultStatusObject().setResponseData(decryptedMessage);

        stepLogger.writeItem(
                getStep().id() + "-response-decrypt",
                "Decrypted Response",
                "Following data were decrypted",
                "OK",
                decryptedMessage
        );
    }

}
