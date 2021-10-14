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
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.io.IOException;

/**
 * Service for managing activation status object based on a file
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@ConditionalOnProperty(prefix = "resultstatus", name = "persistenceType", havingValue = "file", matchIfMissing = true)
@Service
public class ResultStatusFileService implements ResultStatusService {

    /**
     * Stores the result status object into a file
     *
     * @param model Data model with a result status object
     * @throws IOException when an error during saving the result status object to the file occurred
     */
    public void save(ResultStatusChangeable model) throws IOException {
        String formatted = RestClientConfiguration.defaultMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(model.getResultStatus());
        try (FileWriter file = new FileWriter(model.getStatusFileName())) {
            file.write(formatted);
        }
    }

}
