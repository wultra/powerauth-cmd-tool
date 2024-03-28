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
package io.getlime.security.powerauth.lib.cmd.util;

import io.getlime.security.powerauth.lib.cmd.exception.PowerAuthCmdException;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import jakarta.annotation.Nullable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Helper class for reading data from files.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
public class FileUtil {

    /**
     * Read the contents of a provided data file.
     *
     * @param stepLogger      Logger for error handling.
     * @param filePath        Path of the file.
     * @param logFileId       File id used for logging messages.
     * @param fileDescription Description of the file
     * @return Bytes with the contents of the file.
     * @throws IOException           In case reading the file failed.
     * @throws PowerAuthCmdException In case the filename is null or a file does not exist.
     */
    public static byte[] readFileBytes(StepLogger stepLogger,
                                       @Nullable String filePath,
                                       String logFileId,
                                       String fileDescription) throws IOException, PowerAuthCmdException {
        // check if the file was provided
        if (filePath == null) { // filename was not provided, we are assuming empty data and log a warning
            stepLogger.writeItem(
                    "generic-warning-" + logFileId + "-empty",
                    "Empty " + fileDescription + " file",
                    "File not provided, assuming empty data.",
                    "WARNING",
                    null
            );
            return new byte[0];
        }

        Path path = Paths.get(filePath);
        if (Files.isReadable(path)) {
            return Files.readAllBytes(path);
        } else {
            stepLogger.writeItem(
                    "generic-error-" + logFileId + "-file-invalid",
                    "Invalid " + fileDescription + " file",
                    String.format("Unable to read %s - did you specify the correct path?", fileDescription),
                    "ERROR",
                    null
            );
            throw new PowerAuthCmdException();
        }
    }

    /**
     * Reads data from a provided file
     *
     * @param stepLogger      Step logger
     * @param filePath        Path of the file
     * @param cls             Class of the returned data
     * @param logFileId       File id used for logging messages
     * @param fileDescription Description of the file
     * @param <T>             Class type of the returned data
     * @return File data converted to the desired type
     * @throws Exception when an error during file data reading occurred
     */
    public static <T> T readDataFromFile(StepLogger stepLogger, String filePath, Class<T> cls, String logFileId, String fileDescription) throws Exception {
        byte[] fileBytes = readFileBytes(stepLogger, filePath, logFileId, fileDescription);

        T data;
        try {
            data = RestClientConfiguration.defaultMapper().readValue(fileBytes, cls);
        } catch (Exception e) {
            stepLogger.writeItem(
                    "generic-error-" + logFileId + "-file-invalid",
                    "Invalid " + fileDescription + " file",
                    String.format("The %s must be in a correct JSON format", fileDescription),
                    "ERROR",
                    e
            );
            throw new PowerAuthCmdException();
        }
        return data;
    }

}
