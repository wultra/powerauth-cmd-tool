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
package io.getlime.security.powerauth.lib.cmd.logging;

import java.util.Map;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
public interface StepLogger {

    /**
     * Start the object streaming, outputs start of the JSON object:
     */
    void start();

    /**
     * Writes a JSON object representing the step of the execution.
     * @param name Step name.
     * @param description Step detailed description.
     * @param status Step status result.
     * @param object Custom object associated with the step.
     */
    void writeItem(String name, String description, String status, Object object);

    /**
     * Write the information about the server call. Uses "writeItem" method under the hood.
     * @param uri URI that will be called.
     * @param method HTTP method of the call.
     * @param requestObject Request object, in case of the POST, PUT, DELETE method.
     * @param headers HTTP request headers.
     */
    void writeServerCall(String uri, String method, Object requestObject, Map<String, ?> headers);

    /**
     * Write information about the successful server request. Uses "writeItem" method under the hood.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    void writeServerCallOK(Object responseObject, Map<String, ?> headers);

    /**
     * Write information about the failed server request. Uses "writeItem" method under the hood.
     * @param statusCode HTTP response status code.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    void writeServerCallError(int statusCode, Object responseObject, Map<String, ?> headers);

    /**
     * Closes the logger output, writes code to close the array and opened object
     */
    void close();

    /**
     * Write error in case of a network issues.
     * @param e Network exception.
     */
    void writeServerCallConnectionError(Exception e);

    /**
     * Write error with given error message. Error message is mapped as a step description.
     * @param errorMessage Error message.
     */
    void writeError(String errorMessage);

    /**
     * Write error with given exception information. Exception description is mapped as a step description,
     * exception is passed as a custom object.
     * @param exception Exception that should be logged.
     */
    void writeError(Exception exception);

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param name Error name.
     * @param errorMessage Error message.
     */
    void writeError(String name, String errorMessage);

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param name Error name.
     * @param errorMessage Error message.
     * @param exception Exception that caused the error.
     */
    void writeError(String name, String errorMessage, Exception exception);

    /**
     * Write information about successfully finished execution.
     */
    void writeDoneOK();

    /**
     * Write information about incorrectly finished execution.
     */
    void writeDoneFailed();
}
