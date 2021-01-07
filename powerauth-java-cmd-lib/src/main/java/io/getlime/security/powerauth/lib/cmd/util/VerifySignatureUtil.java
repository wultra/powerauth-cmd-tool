/*
 * PowerAuth Command-line utility
 * Copyright 2020 Wultra s.r.o.
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
package io.getlime.security.powerauth.lib.cmd.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;

import java.io.Console;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

public class VerifySignatureUtil {

    /**
     * Extract request data bytes for signature verification.
     *
     * @param model Verify signature step model.
     * @param stepLogger Step logger.
     * @return Request data bytes.
     * @throws URISyntaxException In case URI is invalid.
     * @throws IOException In case of any IO error.
     */
    public static byte[] extractRequestDataBytes(VerifySignatureStepModel model, StepLogger stepLogger) throws URISyntaxException, IOException {
        byte[] requestDataBytes;
        if ("GET".equals(model.getHttpMethod().toUpperCase())) {
            String query = new URI(model.getUriString()).getRawQuery();
            String canonizedQuery = PowerAuthRequestCanonizationUtils.canonizeGetParameters(query);
            if (canonizedQuery != null) {
                requestDataBytes = canonizedQuery.getBytes(StandardCharsets.UTF_8);
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "signature-verify-normalize-data",
                            "Normalized GET data",
                            "GET query data were normalized into the canonical string.",
                            "OK",
                            canonizedQuery
                    );
                }
            } else {
                requestDataBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "signature-verify-empty-data",
                            "Empty data",
                            "No GET query parameters found in provided URL, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        } else {
            // Read data input file
            requestDataBytes = model.getData();
            if (requestDataBytes != null && requestDataBytes.length > 0) {
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "signature-verify-request-payload",
                            "Request payload",
                            "Data from the request payload file, used as the POST / DELETE / ... method body, encoded as Base64.",
                            "OK",
                            BaseEncoding.base64().encode(requestDataBytes)
                    );
                }
            } else {
                requestDataBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "signature-verify-empty-data",
                            "Empty data",
                            "Data file was not found, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        }
        return requestDataBytes;
    }

    /**
     * Get knowledge key unlock password.
     *
     * @param model Verify signature step model.
     * @return Knowledge key unlock password.
     */
    public static char[] getKnowledgeKeyPassword(VerifySignatureStepModel model) {
        char[] password;
        if (model.getPassword() == null) {
            // Ask for the password to unlock knowledge factor key
            Console console = System.console();
            password = console.readPassword("Enter your password to unlock the knowledge related key: ");
        } else {
            // Password is stored in model
            password = model.getPassword().toCharArray();
        }
        return password;
    }
}
