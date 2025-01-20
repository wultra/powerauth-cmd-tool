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
package com.wultra.security.powerauth.lib.cmd.status;

import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import jakarta.annotation.Nullable;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Holder of result statuses in memory
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Component
public class ResultStatusMemoryHolder {

    private final Map<String, ResultStatusObject> resultStatusByActivationId = new HashMap<>();

    /**
     * Provides an activation status by activationId
     * @param activationId Activation ID
     * @return Activation status belonging to the specified activation ID
     */
    public @Nullable ResultStatusObject getByActivationId(String activationId) {
        return resultStatusByActivationId.get(activationId);
    }

    /**
     * Stores an activation status for the specified activation ID
     * @param activationId Activation ID
     * @param status Activation status data
     */
    public void put(String activationId, ResultStatusObject status) {
        resultStatusByActivationId.put(activationId, status);
    }

}
