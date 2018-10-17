/*
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

import io.getlime.security.powerauth.lib.cmd.logging.model.*;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Object-based step logger useful for tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ObjectStepLogger implements StepLogger {

    // Working storage
    private final List<StepItem> items;
    private final List<StepError> errors;
    private StepRequest request;
    private StepResponse response;
    private StepResult result;

    // Optional output stream for logging
    private OutputStream out;

    /**
     * Default constructor with no logging.
     */
    public ObjectStepLogger() {
        this(null);
    }

    /**
     * Constructor with output stream.
     * @param out Output stream for logging.
     */
    public ObjectStepLogger(OutputStream out) {
        this.out = out;
        items = new ArrayList<>();
        errors = new ArrayList<>();
    }

    @Override
    public void start() {
        // Nothing to do
    }

    @Override
    public void writeItem(String name, String description, String status, Object object) {
        items.add(new StepItem(name, description, status, object));
        if (out != null) {
            String output = status + ": " + name + (description == null ? "" : " - " + description + "\n");
            try {
                out.write(output.getBytes());
            } catch (IOException e) {
                // Nothing to do
            }
        }
    }

    /**
     * Write the information about the server call. Uses "writeItem" method under the hood.
     * @param uri URI that will be called.
     * @param method HTTP method of the call.
     * @param requestObject Request object, in case of the POST, PUT, DELETE method.
     * @param headers HTTP request headers.
     */
    @Override
    public void writeServerCall(String uri, String method, Object requestObject, Map<String, ?> headers) {
        if (request != null) {
            throw new IllegalStateException("Only one request per step is supported");
        }
        request = new StepRequest(uri, method, requestObject, headers);
        Map<String, Object> map = new HashMap<>();
        map.put("url", uri);
        map.put("method", method);
        map.put("requestObject", requestObject);
        map.put("requestHeaders", headers);
        String name = "Sending Request";
        String desc = "Calling PowerAuth Standard RESTful API endpoint";
        String status = "OK";
        writeItem(name, desc, status, map);
    }

    /**
     * Write information about the successful server request. Uses "writeItem" method under the hood.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    @Override public void writeServerCallOK(Object responseObject, Map<String, ?> headers) {
        if (response != null) {
            throw new IllegalStateException("Only one response per step is supported");
        }
        response = new StepResponse(200, responseObject, headers);
        String name = "Response 200 - OK";
        String desc = "Endpoint was called successfully";
        String status = "OK";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    @Override
    public void writeServerCallError(int statusCode, Object responseObject, Map<String, ?> headers) {
        if (response != null) {
            throw new IllegalStateException("Only one response per step is supported");
        }
        response = new StepResponse(statusCode, responseObject, headers);
        String name = "Response " + statusCode + " - ERROR";
        String desc = "Endpoint was called with an error";
        String status = "ERROR";
        Map<String, Object> map = new HashMap<>();
        map.put("responseObject", responseObject);
        map.put("responseHeaders", headers);
        writeItem(name, desc, status, map);
    }

    @Override
    public void close() {
        // Nothing to do
    }

    @Override
    public void writeServerCallConnectionError(Exception e) {
        writeError("Connection Error", e.getMessage(), e);
    }

    @Override
    public void writeError(String errorMessage) {
        writeError(null, errorMessage, null);
    }

    @Override
    public void writeError(Exception exception) {
        writeError(null, exception.getMessage(), exception);
    }

    @Override
    public void writeError(String name, String errorMessage) {
        writeError(name, errorMessage, null);
    }

    @Override
    public void writeError(String name, String errorMessage, Exception exception) {
        errors.add(new StepError(name, exception.getMessage(), exception));
        String status = "ERROR";
        writeItem(name, errorMessage, status, exception);
    }

    @Override
    public void writeDoneOK() {
        if (result != null) {
            throw new IllegalStateException("Only one result per step is supported");
        }
        if (!errors.isEmpty()) {
            writeDoneFailed();
            return;
        }
        result = new StepResult(true);
        String name = "Done";
        String desc = "Execution has successfully finished";
        String status = "DONE";
        writeItem(name, desc, status, null);
    }

    @Override
    public void writeDoneFailed() {
        if (result != null) {
            throw new IllegalStateException("Only one result per step is supported");
        }
        result = new StepResult(false);
        String name = "Done";
        String desc = "Execution has failed";
        String status = "FAILED";
        writeItem(name, desc, status, null);
    }

    /**
     * Get step items.
     * @return Step items.
     */
    public List<StepItem> getItems() {
        return items;
    }

    /**
     * Get step errors.
     * @return Step errors.
     */
    public List<StepError> getErrors() {
        return errors;
    }

    /**
     * Get request.
     * @return Request.
     */
    public StepRequest getRequest() {
        return request;
    }

    /**
     * Get response.
     * @return Response.
     */
    public StepResponse getResponse() {
        return response;
    }

    /**
     * Get step result.
     * @return Step result.
     */
    public StepResult getResult() {
        return result;
    }
}
