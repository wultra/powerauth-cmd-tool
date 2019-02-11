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
import java.nio.file.Files;
import java.nio.file.Paths;

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
        byte[] dataFileBytes;
        if ("GET".equals(model.getHttpMethod().toUpperCase())) {
            String query = new URI(model.getUriString()).getRawQuery();
            String canonizedQuery = PowerAuthRequestCanonizationUtils.canonizeGetParameters(query);
            if (canonizedQuery != null) {
                dataFileBytes = canonizedQuery.getBytes(StandardCharsets.UTF_8);
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Normalized GET data",
                            "GET query data were normalized into the canonical string.",
                            "OK",
                            canonizedQuery
                    );
                }
            } else {
                dataFileBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Empty data",
                            "No GET query parameters found in provided URL, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        } else {
            // Read data input file
            if (model.getDataFileName() != null && Files.exists(Paths.get(model.getDataFileName()))) {
                dataFileBytes = Files.readAllBytes(Paths.get(model.getDataFileName()));
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Request payload",
                            "Data from the request payload file, used as the POST / DELETE / ... method body, encoded as Base64.",
                            "OK",
                            BaseEncoding.base64().encode(dataFileBytes)
                    );
                }
            } else {
                dataFileBytes = new byte[0];
                if (stepLogger != null) {
                    stepLogger.writeItem(
                            "Empty data",
                            "Data file was not found, signature will contain no data",
                            "WARNING",
                            null
                    );
                }
            }
        }
        return dataFileBytes;
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
