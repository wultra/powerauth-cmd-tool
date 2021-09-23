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
package io.getlime.security.powerauth.lib.cmd.steps.model.feature;

import io.getlime.security.powerauth.lib.cmd.steps.model.data.BaseStepData;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;

/**
 * Supports change of activation status object
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public interface ResultStatusChangeable extends BaseStepData {

    /**
     * @return Activation status object
     */
    ResultStatusObject getResultStatus();

    /**
     * Sets activation status object
     *
     * @param resultStatusObject Activation status object
     */
    void setResultStatus(ResultStatusObject resultStatusObject);

    /**
     * @return Activation status file name
     */
    String getStatusFileName();

}
