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
package io.getlime.security.powerauth.lib.cmd.steps;

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;

import java.util.List;
import java.util.Map;

/**
 * Interface for objects implementing execution steps.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Petr Dvorak, petr@wultra.com
 */
public interface BaseStep {

    /**
     * Execute this step with given context objects.
     *
     * @param context Context objects.
     * @return Result status object (with current activation status), null in case of failure.
     * @throws Exception In case of a failure.
     */
    ResultStatusObject execute(Map<String, Object> context) throws Exception;

    /**
     * @return Corresponding PowerAuth step
     */
    PowerAuthStep getStep();

    /**
     * @return Supported versions of PowerAuth
     */
    List<PowerAuthVersion> getSupportedVersions();

}
