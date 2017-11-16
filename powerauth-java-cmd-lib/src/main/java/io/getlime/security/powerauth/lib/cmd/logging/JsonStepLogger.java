/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Class responsible for logging the steps performed during the processes to the JSON structure.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class JsonStepLogger implements StepLogger {

    private JsonGenerator generator;
    private OutputStream outputStream;

    /**
     * Create a new logger that outputs to the stream.
     * @param outputStream Output stream.
     */
    public JsonStepLogger(OutputStream outputStream) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        DefaultPrettyPrinter pp = new DefaultPrettyPrinter();
        pp.indentArraysWith( DefaultIndenter.SYSTEM_LINEFEED_INSTANCE );
        pp.indentObjectsWith( DefaultIndenter.SYSTEM_LINEFEED_INSTANCE );
        mapper.setDefaultPrettyPrinter(pp);
        try {
            this.generator = mapper.getFactory().createGenerator(outputStream);
            this.generator.setPrettyPrinter(pp);
            this.outputStream = outputStream;
        } catch (IOException e) {
            //
        }
    }

    /**
     * Flush the logger buffer.
     */
    private void flush() {
        try {
            generator.flush();
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Start the object streaming, outputs start of the JSON object:
     *
     * // {
     * //    "steps" : [
     *
     */
    @Override public void start() {
        try {
            generator.writeStartObject();
            generator.writeFieldName("steps");
            generator.writeStartArray();
            flush();
        } catch (IOException e) {
            //
        }
    }

    /**
     * Writes a JSON object representing the step of the execution.
     * @param name Step name.
     * @param description Step detailed description.
     * @param status Step status result.
     * @param object Custom object associated with the step.
     */
    @Override public void writeItem(String name, String description, String status, Object object) {
        try {
            Map<String, Object> map = new HashMap<>();
            map.put("name", name);
            map.put("description", description);
            map.put("status", status);
            map.put("object", object);
            generator.writeObject(map);
            flush();
        } catch (IOException e) {
            //
        }
    }

    /**
     * Write the information about the server call. Uses "writeItem" method under the hood.
     * @param uri URI that will be called.
     * @param method HTTP method of the call.
     * @param requestObject Request object, in case of the POST, PUT, DELETE method.
     * @param headers HTTP request headers.
     */
    @Override public void writeServerCall(String uri, String method, Object requestObject, Map<String, ?> headers) {
        Map<String, Object> map = new HashMap<>();
        map.put("url", uri);
        map.put("method", method);
        map.put("requestObject", requestObject);
        map.put("requestHeaders", headers);
        String name = "Sending Request";
        String desc = "Calling PowerAuth 2.0 Standard RESTful API endpoint";
        String status = "OK";
        writeItem(name, desc, status, map);
    }

    /**
     * Write information about the successful server request. Uses "writeItem" method under the hood.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    @Override public void writeServerCallOK(Object responseObject, Map<String, ?> headers) {
        String name = "Response 200 - OK";
        String desc = "Endpoint was called successfully";
        String status = "OK";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    /**
     * Write information about the failed server request. Uses "writeItem" method under the hood.
     * @param statusCode HTTP response status code.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    @Override public void writeServerCallError(int statusCode, Object responseObject, Map<String, ?> headers) {
        String name = "Response " + statusCode + " - ERROR";
        String desc = "Endpoint was called with an error";
        String status = "ERROR";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    /**
     * Closes the logger output, writes code to close the array and opened object:
     *
     * //     ]
     * // }
     *
     */
    @Override public void close() {
        try {
            generator.writeEndArray();
            generator.writeEndObject();
            flush();
            generator.close();
        } catch (IOException e) {
            //
        }
    }

    /**
     * Write error in case of a network issues.
     * @param e Network exception.
     */
    @Override public void writeServerCallConnectionError(Exception e) {
        String name = "Connection Error";
        String desc = "Connection refused";
        String status = "ERROR";
        writeItem(name, desc, status, e);
    }

    /**
     * Write error with given error message. Error message is mapped as a step description.
     * @param errorMessage Error message.
     */
    @Override public void writeError(String errorMessage) {
        writeError(null, errorMessage, null);
    }

    /**
     * Write error with given exception information. Exception description is mapped as a step description,
     * exception is passed as a custom object.
     * @param exception Exception that should be logged.
     */
    @Override public void writeError(Exception exception) {
        writeError(null, exception.getMessage(), exception);
    }

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param name Error name.
     * @param errorMessage Error message.
     */
    @Override public void writeError(String name, String errorMessage) {
        writeError(name, errorMessage, null);
    }

    /**
     * Write error with given error name and error message, that is used as a description.
     * @param name Error name.
     * @param errorMessage Error message.
     * @param exception Exception that caused the error.
     */
    @Override public void writeError(String name, String errorMessage, Exception exception) {
        String status = "ERROR";
        writeItem(name, errorMessage, status, exception);
    }

    /**
     * Write information about successfully finished execution.
     */
    @Override public void writeDoneOK() {
        String name = "Done";
        String desc = "Execution has successfully finished";
        String status = "DONE";
        writeItem(name, desc, status, null);
    }

    /**
     * Write information about incorrectly finished execution.
     */
    @Override public void writeDoneFailed() {
        String name = "Done";
        String desc = "Execution has failed";
        String status = "FAILED";
        writeItem(name, desc, status, null);
    }

}
