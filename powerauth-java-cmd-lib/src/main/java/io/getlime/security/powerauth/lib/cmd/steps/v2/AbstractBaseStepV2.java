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
package io.getlime.security.powerauth.lib.cmd.steps.v2;

import com.google.common.collect.ImmutableList;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.BaseStep;
import lombok.Getter;

import java.util.List;

/**
 * Abstract class for PowerAuth steps at version 2
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public abstract class AbstractBaseStepV2 implements BaseStep {

    /**
     * Corresponding PowerAuth step
     */
    @Getter
    private final PowerAuthStep step;

    /**
     * Supported versions of PowerAuth
     */
    @Getter
    private final ImmutableList<PowerAuthVersion> supportedVersions;

    /**
     * Step logger instance
     */
    protected StepLogger stepLogger;

    /**
     * Constructor
     *
     * @param step              PowerAuth step
     * @param supportedVersions Supported versions of PowerAuth
     * @param stepLogger        Step logger instance
     */
    public AbstractBaseStepV2(PowerAuthStep step, List<PowerAuthVersion> supportedVersions,
                              StepLogger stepLogger) {
        this.step = step;
        this.supportedVersions = ImmutableList.copyOf(supportedVersions);

        this.stepLogger = stepLogger;
    }

}
