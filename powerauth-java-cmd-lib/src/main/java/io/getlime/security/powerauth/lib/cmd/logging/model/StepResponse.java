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
package io.getlime.security.powerauth.lib.cmd.logging.model;

import java.util.Map;

/**
 * Class representing response from intermediate server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StepResponse {

    private final int statusCode;
    private final Object responseObject;
    private final Map<String, ?> headers;

    /**
     * Constructor with all details.
     *
     * @param statusCode HTTP status code.
     * @param responseObject Response object.
     * @param headers HTTP headers.
     */
    public StepResponse(int statusCode, Object responseObject, Map<String, ?> headers) {
        this.statusCode = statusCode;
        this.responseObject = responseObject;
        this.headers = headers;
    }

    /**
     * Get HTTP status code.
     * @return HTTP status code.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Get response object.
     * @return Response object.
     */
    public Object getResponseObject() {
        return responseObject;
    }

    /**
     * Get HTTP headers.
     * @return HTTP headers.
     */
    public Map<String, ?> getHeaders() {
        return headers;
    }
}
