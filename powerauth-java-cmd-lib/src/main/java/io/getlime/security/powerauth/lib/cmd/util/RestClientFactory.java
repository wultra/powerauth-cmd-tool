/*
 * PowerAuth Command-line utility
 * Copyright 2020 Wultra s.r.o.
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

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rest Client factory with configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RestClientFactory {

    private static final Logger logger = LoggerFactory.getLogger(RestClientFactory.class);

    private static RestClient restClient;
    private static boolean acceptInvalidSslCertificate;

    /**
     * Get RestClient instance.
     * @return RestClient instance.
     */
    public static RestClient getRestClient() {
        if (restClient != null) {
            return restClient;
        }
        try {
            restClient = DefaultRestClient.builder()
                    .acceptInvalidCertificate(acceptInvalidSslCertificate)
                    .build();
            return restClient;
        } catch (RestClientException ex) {
            logger.error(ex.getMessage(), ex);
        }
        return null;
    }

    /**
     * Get whether invalid SSL certificate is accepted.
     * @return Whether invalid SSL certificate is accepted.
     */
    public static boolean isAcceptInvalidSslCertificate() {
        return acceptInvalidSslCertificate;
    }

    /**
     * Set whether invalid SSL certificate is accepted.
     * @param acceptInvalidSslCertificate Whether invalid SSL certificate is accepted.
     */
    public static void setAcceptInvalidSslCertificate(boolean acceptInvalidSslCertificate) {
        RestClientFactory.acceptInvalidSslCertificate = acceptInvalidSslCertificate;
    }
}
