/*
 * PowerAuth Command-line utility
 * Copyright 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.service;

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.exception.PowerAuthCmdException;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import io.getlime.security.powerauth.lib.cmd.steps.StepProvider;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service for execution of PowerAuth step processes
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Service
public class StepExecutionService {

    /**
     * Step logger
     */
    private final StepLogger stepLogger;

    /**
     * Provider of steps
     */
    private final StepProvider stepProvider;

    /**
     * Constructor
     *
     * @param stepLogger Step logger
     * @param stepProvider Provider of steps
     */
    @Autowired
    public StepExecutionService(
            StepLogger stepLogger,
            StepProvider stepProvider) {
        this.stepLogger = stepLogger;
        this.stepProvider = stepProvider;
    }

    /**
     * Executes the provided step at desired version with the model data
     *
     * @param stepId PowerAuth step identification
     * @param version PowerAuth step version
     * @param model Model data
     * @return Activation status after execution of the step
     * @throws Exception when an error during the step execution occurred
     */
    public ResultStatusObject execute(PowerAuthStep stepId, PowerAuthVersion version, BaseStepModel model) throws Exception {
        if (!stepProvider.exists(stepId)) {
            stepLogger.writeItem(
                    "generic-error-step",
                    "Unsupported step",
                    "The step you specified is not supported: " + stepId,
                    "ERROR",
                    null
            );
            throw new PowerAuthCmdException();
        }

        final BaseStep step = stepProvider.getStep(stepId, version);

        final ResultStatusObject result = step.execute(stepLogger, model.toMap());
        if (result == null) {
            throw new PowerAuthCmdException();
        }
        return result;
    }

}
