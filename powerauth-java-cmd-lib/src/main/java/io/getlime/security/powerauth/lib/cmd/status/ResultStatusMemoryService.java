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
package io.getlime.security.powerauth.lib.cmd.status;

import io.getlime.security.powerauth.lib.cmd.steps.model.feature.ResultStatusChangeable;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * Service for managing activation status objects based in memory
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@ConditionalOnProperty(prefix = "resultstatus", name = "persistenceType", havingValue = "memory")
@Service
public class ResultStatusMemoryService implements ResultStatusService {

    private final ResultStatusMemoryHolder resultStatusMemoryHolder;

    @Autowired
    public ResultStatusMemoryService(ResultStatusMemoryHolder resultStatusMemoryHolder) {
        this.resultStatusMemoryHolder = resultStatusMemoryHolder;
    }

    @Override
    public void save(ResultStatusChangeable model) throws IOException {
        ResultStatusObject status = model.getResultStatusObject();
        resultStatusMemoryHolder.put(status.getActivationId(), status);
    }

}
