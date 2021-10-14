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
package io.getlime.security.powerauth.lib.cmd.steps.context;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.springframework.http.HttpMethod;

import java.util.HashMap;
import java.util.Map;

/**
 * Request context
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
@Data
@Builder
@ToString(of = {"httpMethod", "uri", "requestObject"})
public class RequestContext {

    /**
     * Authorization header value
     */
    private String authorizationHeader;

    /**
     * Authorization header name
     */
    private String authorizationHeaderName;

    /**
     * HTTP request method
     */
    @Builder.Default
    private HttpMethod httpMethod = HttpMethod.POST;

    /**
     * HTTP headers related to the request context
     */
    @Builder.Default
    private Map<String, String> httpHeaders = new HashMap<>();

    /**
     * Raw request object
     */
    private Object requestObject;

    /**
     * HTTP method used for a signature computation
     */
    private String signatureHttpMethod;

    /**
     * URI used for a signature computation
     */
    private String signatureRequestUri;

    /**
     * Server uri
     */
    private String uri;

}
