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

import io.getlime.core.rest.model.base.request.ObjectRequest;

import java.util.Map;

/**
 * Class representing a request sent to intermediate server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class StepRequest {

    private final String uri;
    private final String method;
    private final Object requestObject;
    private final Map<String, ?> headers;

    /**
     * Constructor with request details.
     * @param uri Request URI.
     * @param method Request HTTP method.
     * @param requestObject Request object.
     * @param headers Request HTTP headers.
     */
    public StepRequest(String uri, String method, Object requestObject, Map<String, ?> headers) {
        this.uri = uri;
        this.method = method;
        this.requestObject = requestObject;
        this.headers = headers;
    }

    /**
     * Get request URI.
     * @return Request URI.
     */
    public String getUri() {
        return uri;
    }

    /**
     * Get request HTTP method.
     * @return Request HTTP method.
     */
    public String getMethod() {
        return method;
    }

    /**
     * Get request object.
     * @return Request object.
     */
    public Object getRequestObject() {
        if (requestObject instanceof ObjectRequest) {
            return ((ObjectRequest<?>) requestObject).getRequestObject();
        }
        return requestObject;
    }

    /**
     * Get request HTTP headers.
     * @return Request HTTP headers.
     */
    public Map<String, ?> getHeaders() {
        return headers;
    }
}
