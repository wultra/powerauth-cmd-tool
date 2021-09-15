/*
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

import com.google.common.collect.ImmutableMap;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthConst;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.PowerAuthHeaderService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;
import io.getlime.security.powerauth.lib.cmd.steps.AbstractBaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.context.RequestContext;
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext;
import io.getlime.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.UpgradeResponsePayload;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Step for starting upgrade to PowerAuth protocol version 3.0.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *      <li>3.0</li>
 *      <li>3.1</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class StartUpgradeStep extends AbstractBaseStep<StartUpgradeStepModel, EciesEncryptedResponse> {

    private final PowerAuthHeaderService powerAuthHeaderService;

    @Autowired
    public StartUpgradeStep(PowerAuthHeaderService powerAuthHeaderService,
                            ResultStatusService resultStatusService,
                            StepLogger stepLogger) {
        super(PowerAuthStep.UPGRADE_START, PowerAuthVersion.VERSION_3, resultStatusService, stepLogger);

        this.powerAuthHeaderService = powerAuthHeaderService;
    }

    @Override
    protected ParameterizedTypeReference<EciesEncryptedResponse> getResponseTypeReference() {
        return PowerAuthConst.RESPONSE_TYPE_REFERENCE_V3;
    }

    @Override
    public StepContext<StartUpgradeStepModel, EciesEncryptedResponse> prepareStepContext(Map<String, Object> context) throws Exception {
        StartUpgradeStepModel model = new StartUpgradeStepModel();
        model.fromMap(context);

        RequestContext requestContext = RequestContext.builder()
                .uri(model.getUriString() + "/pa/v3/upgrade/start")
                .build();

        StepContext<StartUpgradeStepModel, EciesEncryptedResponse> stepContext =
                buildStepContext(model, requestContext);

        addEncryptedRequest(stepContext, model.getApplicationSecret(), EciesSharedInfo1.UPGRADE, PowerAuthConst.EMPTY_JSON_BYTES);

        powerAuthHeaderService.addEncryptionHeader(requestContext, model);

        return stepContext;
    }

    @Override
    public void processResponse(StepContext<StartUpgradeStepModel, EciesEncryptedResponse> stepContext) throws Exception {
        StartUpgradeStepModel model = stepContext.getModel();
        EciesEncryptor encryptor = stepContext.getEncryptor();
        EciesEncryptedResponse response = stepContext.getResponseContext().getResponseBodyObject();
        final UpgradeResponsePayload responsePayload =
                decryptResponse(encryptor, response, UpgradeResponsePayload.class);

        // Store the activation status (updated counter)
        model.getResultStatusObject().setCtrDataBase(responsePayload.getCtrData());
        resultStatusService.save(model);

        stepLogger.writeItem(
                getStep().id() + "-completed",
                "Upgrade start step successfully completed",
                "Upgrade start step was successfully completed",
                "OK",
                ImmutableMap.of("ctrData", responsePayload.getCtrData())
        );
    }

}
