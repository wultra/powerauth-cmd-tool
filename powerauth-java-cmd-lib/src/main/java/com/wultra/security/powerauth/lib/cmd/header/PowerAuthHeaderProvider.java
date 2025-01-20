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
package com.wultra.security.powerauth.lib.cmd.header;

import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.data.BaseStepData;

/**
 * Interface to be implemented by all PowerAuth header providers
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public interface PowerAuthHeaderProvider<M extends BaseStepData> {

    /**
     * Adds PowerAuth header to the step context
     * @param stepContext Step context
     * @throws Exception When an error during adding of the PowerAuth header occurred
     */
    void addHeader(StepContext<? extends M, ?> stepContext) throws Exception;

}
