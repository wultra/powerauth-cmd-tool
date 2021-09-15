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
package io.getlime.security.powerauth.lib.cmd;

import io.getlime.security.powerauth.lib.cmd.logging.DisabledStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.config.StepLoggerConfig;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * An application to initiate and provide command line library features
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@SpringBootApplication
public class CmdLibApplication {

    /**
     * Configures and creates a step logger for the application
     * @param config Configuration
     * @return Step logger instance
     */
    @Bean
    public StepLogger stepLogger(StepLoggerConfig config) {
        switch (config.getType()) {
            case DISABLED:
                return new DisabledStepLogger();
            case JSON:
                return new JsonStepLogger(System.out);
            case OBJECT:
                return new ObjectStepLogger(System.out);
            default:
                throw new IllegalStateException("Not supported step logger type: " + config.getType());
        }
    }

}
