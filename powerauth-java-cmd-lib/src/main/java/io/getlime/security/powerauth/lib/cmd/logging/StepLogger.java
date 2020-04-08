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
     * Start the object streaming, outputs start of the result object:
     */
    void start();

    /**
     * Writes an object representing the step of the execution.
     * @param id Step ID.
     * @param name Step name.
     * @param description Step detailed description.
     * @param status Step status result.
     * @param object Custom object associated with the step.
     */
    void writeItem(String id, String name, String description, String status, Object object);

    /**
     * Write the information about the server call. Uses "writeItem" method under the hood.
     * @param id Step ID.
     * @param uri URI that will be called.
     * @param method HTTP method of the call.
     * @param requestObject Request object, in case of the POST, PUT, DELETE method.
     * @param headers HTTP request headers.
     */
    void writeServerCall(String id, String uri, String method, Object requestObject, Map<String, ?> headers);

    /**
     * Write information about the successful server request. Uses "writeItem" method under the hood.
     * @param id Step ID.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    void writeServerCallOK(String id, Object responseObject, Map<String, ?> headers);

    /**
     * Write information about the failed server request. Uses "writeItem" method under the hood.
     * @param id Step ID.
     * @param statusCode HTTP response status code.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    void writeServerCallError(String id, int statusCode, Object responseObject, Map<String, ?> headers);

    /**
     * Closes the logger output, writes code to close the array and opened object
     */
    void close();

    /**
     * Write error in case of a network issues.
     * @param id Step ID.
     * @param e Network exception.
     */
    void writeServerCallConnectionError(String id, Exception e);

    /**
     * Write error with given error message. Error message is mapped as a step description.
     * @param id Step ID.
     * @param errorMessage Error message.
     */
    void writeError(String id, String errorMessage);

    /**
     * Write error with given exception information. Exception description is mapped as a step description,
     * exception is passed as a custom object.
     * @param id Step ID.
     * @param exception Exception that should be logged.
     */
    void writeError(String id, Exception exception);

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param id Step ID.
     * @param name Error name.
     * @param errorMessage Error message.
     */
    void writeError(String id, String name, String errorMessage);

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param id Step ID.
     * @param name Error name.
     * @param errorMessage Error message.
     * @param exception Exception that caused the error.
     */
    void writeError(String id, String name, String errorMessage, Exception exception);

    /**
     * Write information about successfully finished execution.
     * @param id Step ID.
     */
    void writeDoneOK(String id);

    /**
     * Write information about incorrectly finished execution.
     * @param id Step ID.
     */
    void writeDoneFailed(String id);
}
