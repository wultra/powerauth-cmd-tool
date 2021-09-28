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
package io.getlime.security.powerauth.lib.cmd.consts;

import io.getlime.security.powerauth.lib.cmd.logging.StepLoggerFactory;
import io.getlime.security.powerauth.lib.cmd.header.PowerAuthHeaderFactory;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusFileService;
import io.getlime.security.powerauth.lib.cmd.status.ResultStatusService;

/**
 * Constants
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class BackwardCompatibilityConst {

    /**
     * Constant bean of result status service
     */
    public static final ResultStatusService RESULT_STATUS_SERVICE = new ResultStatusFileService();

    /**
     * Constant step logger
     */
    public static final StepLoggerFactory STEP_LOGGER_FACTORY;

    /**
     * Constant bean of PowerAuth header service
     */
    public static final PowerAuthHeaderFactory POWER_AUTH_HEADER_FACTORY = new PowerAuthHeaderFactory();

    static {
        STEP_LOGGER_FACTORY = new StepLoggerFactory(StepLoggerType.DISABLED);
    }

}
