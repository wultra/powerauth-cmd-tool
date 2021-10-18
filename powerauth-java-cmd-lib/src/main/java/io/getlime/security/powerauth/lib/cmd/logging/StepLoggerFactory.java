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
package io.getlime.security.powerauth.lib.cmd.logging;

import io.getlime.security.powerauth.lib.cmd.consts.StepLoggerType;
import io.getlime.security.powerauth.lib.cmd.logging.config.StepLoggerConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Step logger factory which allows to create a new {@link StepLogger} instance
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Component
public class StepLoggerFactory {

    private final StepLoggerConfig config;

    /**
     * Constructor
     * @param stepLoggerType Type of used step logger
     */
    public StepLoggerFactory(StepLoggerType stepLoggerType) {
        this.config = new StepLoggerConfig();
        this.config.setType(stepLoggerType);
    }

    /**
     * Constructor
     * @param config Configuration of step logger
     */
    @Autowired
    public StepLoggerFactory(StepLoggerConfig config) {
        this.config = config;
    }

    /**
     * Creates new instance of {@link StepLogger}
     * @return new instance of step logger
     */
    public StepLogger createStepLogger() {
        if (config == null || config.getType() == null) {
            return DisabledStepLogger.INSTANCE;
        }

        switch (config.getType()) {
            case DISABLED:
                return DisabledStepLogger.INSTANCE;
            case JSON:
                return new JsonStepLogger(System.out);
            case OBJECT:
                return new ObjectStepLogger(System.out);
            default:
                throw new IllegalStateException("Unrecognized step logger type: " + config.getType());
        }
    }

}
