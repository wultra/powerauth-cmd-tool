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

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

/**
 * Web Client factory with configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class WebClientFactory {

    private static final Logger logger = LoggerFactory.getLogger(WebClientFactory.class);

    private static WebClient webClient;
    private static boolean acceptInvalidSslCertificate;

    /**
     * Get WebClient instance.
     * @return WebClient instance.
     */
    public static WebClient getWebClient() {
        if (webClient != null) {
            return webClient;
        }
        HttpClient httpClient = HttpClient.create();
        SslContext sslContext;
        try {
            if (acceptInvalidSslCertificate) {
                sslContext = SslContextBuilder
                        .forClient()
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .build();
                httpClient = httpClient.secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
            }
        } catch (SSLException ex) {
            logger.warn(ex.getMessage(), ex);
        }
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
        webClient = WebClient.builder().clientConnector(connector).build();
        return webClient;
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
        WebClientFactory.acceptInvalidSslCertificate = acceptInvalidSslCertificate;
    }
}
