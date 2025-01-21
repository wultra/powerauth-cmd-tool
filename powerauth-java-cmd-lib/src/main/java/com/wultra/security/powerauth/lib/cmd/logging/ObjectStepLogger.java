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
package com.wultra.security.powerauth.lib.cmd.logging;

import com.wultra.security.powerauth.lib.cmd.logging.model.*;

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
    private final OutputStream out;

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

    /**
     * Writes an object representing the step of the execution.
     * @param id Step ID.
     * @param name Step name.
     * @param description Step detailed description.
     * @param status Step status result.
     * @param object Custom object associated with the step.
     */
    @Override
    public void writeItem(String id, String name, String description, String status, Object object) {
        items.add(new StepItem(id, name, description, status, object));
        if (out != null) {
            String output = status + ": " + id + " => " + name + (description == null ? "" : " - " + description) + "\n";
            try {
                out.write(output.getBytes());
            } catch (IOException e) {
                // Nothing to do
            }
        }
    }

    /**
     * Write the information about the server call. Uses "writeItem" method under the hood.
     * @param id Step ID.
     * @param uri URI that will be called.
     * @param method HTTP method of the call.
     * @param requestBytes Request bytes, in case of the POST, PUT, DELETE method.
     * @param requestObject Request object, in case of the POST, PUT, DELETE method.
     * @param headers HTTP request headers.
     */
    @Override
    public void writeServerCall(String id, String uri, String method, Object requestObject, byte[] requestBytes, Map<String, ?> headers) {
        if (request != null) {
            throw new IllegalStateException("Only one request per step is supported");
        }
        request = new StepRequest(uri, method, requestObject, headers);
        Map<String, Object> map = new HashMap<>();
        map.put("url", uri);
        map.put("method", method);
        map.put("requestBytes", requestBytes);
        map.put("requestObject", request.requestObject());
        map.put("requestHeaders", headers);
        String name = "Sending Request";
        String desc = "Calling PowerAuth Standard RESTful API endpoint";
        String status = "OK";
        writeItem(id, name, desc, status, map);
    }

    /**
     * Write information about the successful server request. Uses "writeItem" method under the hood.
     * @param id Step ID.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    @Override public void writeServerCallOK(String id, Object responseObject, Map<String, ?> headers) {
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
        writeItem(id, name, desc, status, map);
    }

    /**
     * Write information about the service call error.
     * @param id Step ID.
     * @param statusCode HTTP response status code.
     * @param responseObject HTTP response object.
     * @param headers HTTP response headers.
     */
    @Override
    public void writeServerCallError(String id, int statusCode, Object responseObject, Map<String, ?> headers) {
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
        writeItem(id, name, desc, status, map);
    }

    @Override
    public void close() {
        // Nothing to do
    }

    /**
     * Write information about service call network connection error.
     * @param id Step ID.
     * @param e Exception that caused the error.
     */
    @Override
    public void writeServerCallConnectionError(String id, Exception e) {
        writeError(id, "Connection Error", e.getMessage(), e);
    }

    /**
     * Write information about an error.
     * @param id Step ID.
     * @param errorMessage Error message.
     */
    @Override
    public void writeError(String id, String errorMessage) {
        writeError(id, null, errorMessage, null);
    }

    /**
     * Write information about an error.
     * @param id Step ID.
     * @param exception Exception that caused the error.
     */
    @Override
    public void writeError(String id, Exception exception) {
        writeError(id, null, exception.getMessage(), exception);
    }

    /**
     * Write information about an error.
     * @param id Step ID.
     * @param name Error item name.
     * @param errorMessage Error message.
     */
    @Override
    public void writeError(String id, String name, String errorMessage) {
        writeError(id, name, errorMessage, null);
    }

    /**
     * Write information about an error.
     * @param id Step ID.
     * @param name Error item name.
     * @param errorMessage Error message.
     * @param exception Exception that caused the error.
     */
    @Override
    public void writeError(String id, String name, String errorMessage, Exception exception) {
        errors.add(new StepError(id, name, errorMessage, exception));
        String status = "ERROR";
        writeItem(id, name, errorMessage, status, exception);
    }

    /**
     * Write information about a successful completion.
     * @param id Step ID.
     */
    @Override
    public void writeDoneOK(String id) {
        if (result != null) {
            throw new IllegalStateException("Only one result per step is supported");
        }
        if (!errors.isEmpty()) {
            writeDoneFailed(id + "-with-errors");
            return;
        }
        result = new StepResult(true);
        String name = "Done";
        String desc = "Execution has successfully finished";
        String status = "DONE";
        writeItem(id, name, desc, status, null);
    }

    /**
     * Write error about a failed execution.
     * @param id Step ID.
     */
    @Override
    public void writeDoneFailed(String id) {
        if (result != null) {
            throw new IllegalStateException("Only one result per step is supported");
        }
        result = new StepResult(false);
        String name = "Done";
        String desc = "Execution has failed";
        String status = "FAILED";
        writeItem(id, name, desc, status, null);
    }

    /**
     * Get step items.
     * @return Step items.
     */
    public List<StepItem> getItems() {
        return items;
    }

    /**
     * Get first {@link StepItem} with given ID.
     * @param id Item ID.
     * @return First {@link StepItem} with given id or {@code null} if logger doesn't contain such item.
     */
    public StepItem getFirstItem(String id) {
        if (id == null) {
            return null;
        }
        for (StepItem item: items) {
            if (id.equals(item.id())) {
                return item;
            }
        }
        return null;
    }

    /**
     * Get first {@link StepItem} with given name.
     * @param itemName Item name.
     * @return First {@link StepItem} with given name or {@code null} if logger doesn't contain such item.
     */
    public StepItem getFirstItemByName(String itemName) {
        if (itemName == null) {
            return null;
        }
        for (StepItem item: items) {
            if (itemName.equals(item.name())) {
                return item;
            }
        }
        return null;
    }

    /**
     * Get step errors.
     * @return Step errors.
     */
    public List<StepError> getErrors() {
        return errors;
    }

    /**
     * Get first {@link StepError} with given name.
     * @param id Error ID.
     * @return First {@link StepError} with given ID or {@code null} if logger doesn't contain such error.
     */
    public StepError getFirstError(String id) {
        if (id == null) {
            return null;
        }
        for (StepError error: errors) {
            if (id.equals(error.id())) {
                return error;
            }
        }
        return null;
    }

    /**
     * Get first {@link StepError} with given name.
     * @param errorName Error name.
     * @return First {@link StepError} with given name or {@code null} if logger doesn't contain such error.
     */
    public StepError getFirstErrorByName(String errorName) {
        if (errorName == null) {
            return null;
        }
        for (StepError error: errors) {
            if (errorName.equals(error.name())) {
                return error;
            }
        }
        return null;
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
