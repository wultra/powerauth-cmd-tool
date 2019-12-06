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
package io.getlime.security.powerauth.app.cmd;

import com.mashape.unirest.http.Unirest;
import io.getlime.security.powerauth.app.cmd.exception.ExecutionException;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.*;
import io.getlime.security.powerauth.lib.cmd.steps.v3.ActivationRecoveryStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CommitUpgradeStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.ConfirmRecoveryCodeStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.StartUpgradeStep;
import io.getlime.security.powerauth.lib.cmd.util.ConfigurationUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.apache.commons.cli.*;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import javax.net.ssl.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Command-line utility for testing PowerAuth implementation and for verification of
 * a correct system deployment.
 *
 * @author Petr Dvorak
 *
 */
public class Application {

    /**
     * Application main
     * @param args Arguments, use --help to print expected arguments
     */
    @SuppressWarnings("unchecked")
    public static void main(String[] args) {

        JsonStepLogger stepLogger = new JsonStepLogger(System.out);

        try {

            JSONObject clientConfigObject;

            // Add Bouncy Castle Security Provider
            Security.addProvider(new BouncyCastleProvider());
            PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());

            // Configure REST client
            RestClientConfiguration.configure();

            // Options definition
            Options options = new Options();
            options.addOption("h", "help", false, "Print this help manual.");
            options.addOption("u", "url", true, "Base URL of the PowerAuth Standard RESTful API.");
            options.addOption("m", "method", true, "What API method to call, available names are 'create', 'status', 'remove', 'sign', 'unlock', 'create-custom', 'create-token', 'validate-token', 'remove-token', 'encrypt', 'sign-encrypt', 'start-upgrade', 'commit-upgrade', 'create-recovery' and 'confirm-recovery-code'.");
            options.addOption("c", "config-file", true, "Specifies a path to the config file with Base64 encoded server master public key, application ID and application secret.");
            options.addOption("s", "status-file", true, "Path to the file with the activation status, serving as the data persistence.");
            options.addOption("a", "activation-code", true, "In case a specified method is 'create', this field contains the activation key (a concatenation of a short activation ID and activation OTP).");
            options.addOption("t", "http-method", true, "In case a specified method is 'sign', this field specifies a HTTP method, as specified in PowerAuth signature process.");
            options.addOption("e", "endpoint", true, "In case a specified method is 'sign', this field specifies a URI identifier, as specified in PowerAuth signature process.");
            options.addOption("l", "signature-type", true, "In case a specified method is 'sign', this field specifies a signature type, as specified in PowerAuth signature process.");
            options.addOption("d", "data-file", true, "In case a specified method is 'sign', this field specifies a file with the input data to be signed and verified with the server, as specified in PowerAuth signature process.");
            options.addOption("p", "password", true, "Password used for a knowledge related key encryption. If not specified, an interactive input is required.");
            options.addOption("I", "identity-file", true, "In case a specified method is 'create-custom', this field specifies the path to the file with identity attributes.");
            options.addOption("C", "custom-attributes-file", true, "In case a specified method is 'create-custom', this field specifies the path to the file with custom attributes.");
            options.addOption("i", "invalidSsl", false, "Client may accept invalid SSL certificate in HTTPS communication.");
            options.addOption("T", "token-id", true, "Token ID (UUID4), in case of 'token-validate' method.");
            options.addOption("S", "token-secret", true, "Token secret (Base64 encoded bytes), in case of 'token-validate' method.");
            options.addOption("r", "reason", true, "Reason why vault is being unlocked.");
            options.addOption("o", "scope", true, "ECIES encryption scope: 'application' or 'activation'.");
            options.addOption("R", "recovery-code", true, "Recovery code to be confirmed.");
            options.addOption("v", "version", true, "PowerAuth protocol version.");

            Option httpHeaderOption = Option.builder("H")
                    .argName("key=value")
                    .longOpt("http-header")
                    .hasArg(true)
                    .desc("Use provided HTTP header for communication")
                    .numberOfArgs(2)
                    .valueSeparator('=')
                    .build();
            options.addOption(httpHeaderOption);

            // Options parsing
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            // Check if help was invoked
            if (cmd.hasOption("h") || !cmd.hasOption("m")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(100);
                formatter.printHelp("java -jar powerauth-java-cmd.jar", options);
                return;
            }

            // Read HTTP headers
            Map<String, String> httpHeaders = new HashMap<>();
            if (cmd.hasOption("H")) {
                Properties props = cmd.getOptionProperties("H");
                final Set<String> propertyNames = props.stringPropertyNames();
                for (String name: propertyNames) {
                    httpHeaders.put(name, props.getProperty(name));
                }
            }

            stepLogger.start();

            // Allow invalid SSL certificates
            if (cmd.hasOption("i")) {

                // Configure default Java HTTP Client
                HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

                TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }};

                try {
                    // Disable certificate validation on
                    SSLContext sc = SSLContext.getInstance("SSL");
                    sc.init(null, trustAllCerts, new java.security.SecureRandom());
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

                    // Set correct HTTP client for Unirest
                    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sc);
                    CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
                    Unirest.setHttpClient(httpclient);

                } catch (Exception e) {
                    //
                }

            }

            // Read values
            String method = cmd.getOptionValue("m");
            String uriString = cmd.getOptionValue("u");
            String statusFileName = cmd.getOptionValue("s");
            String configFileName = cmd.getOptionValue("c");
            String reason = cmd.getOptionValue("r");
            String version = cmd.getOptionValue("v");

            // Default version
            if (version == null) {
                version = "3.1";
            }

            // Read config file
            if (Files.exists(Paths.get(configFileName))) {
                byte[] configFileBytes = Files.readAllBytes(Paths.get(configFileName));
                try {
                    clientConfigObject = (JSONObject) JSONValue.parse(new String(configFileBytes, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    stepLogger.writeItem(
                            "Invalid config file",
                            "Config file must be in a correct JSON format?",
                            "ERROR",
                            e
                    );
                    throw new ExecutionException();
                }
            } else {
                stepLogger.writeItem(
                        "Invalid config file",
                        "Unable to read client config file - did you specify the correct path?",
                        "ERROR",
                        null
                );
                throw new ExecutionException();
            }

            // Read master public key
            PublicKey masterPublicKey = ConfigurationUtil.getMasterKey(clientConfigObject, stepLogger);

            // Read current activation state from the activation state file or create an empty state
            JSONObject resultStatusObject;
            if (statusFileName != null && Files.exists(Paths.get(statusFileName))) {
                byte[] statusFileBytes = Files.readAllBytes(Paths.get(statusFileName));
                resultStatusObject = (JSONObject) JSONValue.parse(new String(statusFileBytes, StandardCharsets.UTF_8));
            } else {
                resultStatusObject = new JSONObject();
            }

            // Execute the code for given methods
            switch (method) {
                case "create-token": {

                    CreateTokenStepModel model = new CreateTokenStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.CreateTokenStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.CreateTokenStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }

                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "validate-token": {

                    VerifyTokenStepModel model = new VerifyTokenStepModel();
                    model.setTokenId(cmd.getOptionValue("T"));
                    model.setTokenSecret(cmd.getOptionValue("S"));
                    model.setHeaders(httpHeaders);
                    model.setDataFileName(cmd.getOptionValue("d"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setVersion(version);

                    JSONObject result = new VerifyTokenStep().execute(stepLogger, model.toMap());
                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "remove-token": {
                    RemoveTokenStepModel model = new RemoveTokenStepModel();
                    model.setTokenId(cmd.getOptionValue("T"));
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.RemoveTokenStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.RemoveTokenStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }

                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "create":
                case "prepare": {

                    if (method.equals("prepare")) {
                        stepLogger.writeItem(
                                "Deprecated method",
                                "Use 'create' method instead of deprecated 'prepare'",
                                "WARNING",
                                null
                        );
                    }

                    PrepareActivationStepModel model = new PrepareActivationStepModel();
                    model.setActivationCode(cmd.getOptionValue("a"));
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "status": {

                    GetStatusStepModel model = new GetStatusStepModel();
                    model.setHeaders(httpHeaders);
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.GetStatusStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "remove": {

                    RemoveStepModel model = new RemoveStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.RemoveStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.RemoveStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "sign": {

                    VerifySignatureStepModel model = new VerifySignatureStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setDataFileName(cmd.getOptionValue("d"));
                    model.setHeaders(httpHeaders);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResourceId(cmd.getOptionValue("e"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result = new VerifySignatureStep().execute(stepLogger, model.toMap());
                    if (result == null) {
                        throw new ExecutionException();
                    }

                    break;
                }
                case "unlock": {

                    VaultUnlockStepModel model = new VaultUnlockStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setUriString(uriString);
                    model.setReason(reason);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.VaultUnlockStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.VaultUnlockStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }
                case "create-custom": {

                    String identityAttributesFileName = cmd.getOptionValue("I");
                    String customAttributesFileName = cmd.getOptionValue("C");

                    Map<String,String> identityAttributes;
                    if (Files.exists(Paths.get(identityAttributesFileName))) {
                        byte[] identityAttributesFileBytes = Files.readAllBytes(Paths.get(identityAttributesFileName));
                        try {
                            identityAttributes = RestClientConfiguration.defaultMapper().readValue(identityAttributesFileBytes, HashMap.class);
                        } catch (Exception e) {
                            stepLogger.writeItem(
                                    "Invalid identity attributes file",
                                    "Identity attribute file must be in a correct JSON format",
                                    "ERROR",
                                    e
                            );
                            throw new ExecutionException();
                        }
                    } else {
                        stepLogger.writeItem(
                                "Invalid identity attributes file",
                                "Unable to read identity attributes file - did you specify the correct path?",
                                "ERROR",
                                null
                        );
                        throw new ExecutionException();
                    }

                    Map<String,Object> customAttributes;
                    if (Files.exists(Paths.get(customAttributesFileName))) {
                        byte[] customAttributesFileBytes = Files.readAllBytes(Paths.get(customAttributesFileName));
                        try {
                            customAttributes = RestClientConfiguration.defaultMapper().readValue(customAttributesFileBytes, HashMap.class);
                        } catch (Exception e) {
                            stepLogger.writeItem(
                                    "Invalid custom attributes file",
                                    "Custom attribute file must be in a correct JSON format",
                                    "ERROR",
                                    e
                            );
                            throw new ExecutionException();
                        }
                    } else {
                        stepLogger.writeItem(
                                "Invalid custom attributes file",
                                "Unable to read custom attributes file - did you specify the correct path?",
                                "ERROR",
                                null
                        );
                        throw new ExecutionException();
                    }

                    CreateActivationStepModel model = new CreateActivationStepModel();
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setActivationOtp(cmd.getOptionValue("a"));
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setCustomAttributes(customAttributes);
                    model.setHeaders(httpHeaders);
                    model.setIdentityAttributes(identityAttributes);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.CreateActivationStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }
                case "encrypt": {
                    EncryptStepModel model = new EncryptStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setResultStatusObject(resultStatusObject);
                    model.setDataFileName(cmd.getOptionValue("d"));
                    model.setScope(cmd.getOptionValue("o"));
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep().execute(stepLogger, model.toMap());
                            break;

                        case "2.0":
                        case "2.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v2.EncryptStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }
                case "sign-encrypt": {
                    VerifySignatureStepModel model = new VerifySignatureStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setDataFileName(cmd.getOptionValue("d"));
                    model.setHeaders(httpHeaders);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResourceId(cmd.getOptionValue("e"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        // Sign and encrypt step is only supported since version 3.0
                        case "3.0":
                        case "3.1":
                            result = new io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }
                case "start-upgrade": {
                    StartUpgradeStepModel model = new StartUpgradeStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setStatusFileName(statusFileName);
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        // Only upgrade to version 3.0 or 3.1 is supported
                        case "3.0":
                        case "3.1":
                            result = new StartUpgradeStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }

                case "commit-upgrade": {
                    CommitUpgradeStepModel model = new CommitUpgradeStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setStatusFileName(statusFileName);
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        // Only upgrade to version 3.0 or 3.1 is supported
                        case "3.0":
                        case "3.1":
                            result = new CommitUpgradeStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }

                case "create-recovery": {
                    String identityAttributesFileName = cmd.getOptionValue("I");
                    String customAttributesFileName = cmd.getOptionValue("C");

                    if (identityAttributesFileName == null) {
                        stepLogger.writeItem(
                                "Missing identity attributes file",
                                "Identity attribute file must be specified",
                                "ERROR",
                                null
                        );
                        throw new ExecutionException();
                    }

                    Map<String,String> identityAttributes;
                    if (Files.exists(Paths.get(identityAttributesFileName))) {
                        byte[] identityAttributesFileBytes = Files.readAllBytes(Paths.get(identityAttributesFileName));
                        try {
                            identityAttributes = RestClientConfiguration.defaultMapper().readValue(identityAttributesFileBytes, HashMap.class);
                        } catch (Exception e) {
                            stepLogger.writeItem(
                                    "Invalid identity attributes file",
                                    "Identity attribute file must be in a correct JSON format",
                                    "ERROR",
                                    e
                            );
                            throw new ExecutionException();
                        }
                    } else {
                        stepLogger.writeItem(
                                "Invalid identity attributes file",
                                "Unable to read identity attributes file - did you specify the correct path?",
                                "ERROR",
                                null
                        );
                        throw new ExecutionException();
                    }

                    Map<String, Object> customAttributes = null;
                    if (customAttributesFileName != null) {
                        if (Files.exists(Paths.get(customAttributesFileName))) {
                            byte[] customAttributesFileBytes = Files.readAllBytes(Paths.get(customAttributesFileName));
                            try {
                                customAttributes = RestClientConfiguration.defaultMapper().readValue(customAttributesFileBytes, HashMap.class);
                            } catch (Exception e) {
                                stepLogger.writeItem(
                                        "Invalid custom attributes file",
                                        "Custom attribute file must be in a correct JSON format",
                                        "ERROR",
                                        e
                                );
                                throw new ExecutionException();
                            }
                        } else {
                            stepLogger.writeItem(
                                    "Invalid custom attributes file",
                                    "Unable to read custom attributes file - did you specify the correct path?",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                        }
                    }

                    ActivationRecoveryStepModel model = new ActivationRecoveryStepModel();
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setIdentityAttributes(identityAttributes);
                    model.setCustomAttributes(customAttributes);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        // Activation recovery is supported since version 3.0
                        case "3.0":
                        case "3.1":
                            result = new ActivationRecoveryStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }

                case "confirm-recovery-code": {
                    ConfirmRecoveryCodeStepModel model = new ConfirmRecoveryCodeStepModel();
                    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject));
                    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setRecoveryCode(cmd.getOptionValue("R"));
                    model.setResultStatusObject(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    JSONObject result;
                    switch (version) {
                        // Recovery code confirmation is supported since version 3.0
                        case "3.0":
                        case "3.1":
                            result = new ConfirmRecoveryCodeStep().execute(stepLogger, model.toMap());
                            break;

                        default:
                            stepLogger.writeItem(
                                    "Unsupported version",
                                    "The version you specified is not supported",
                                    "ERROR",
                                    null
                            );
                            throw new ExecutionException();
                    }
                    if (result == null) {
                        throw new ExecutionException();
                    }
                    break;
                }

                default:
                    HelpFormatter formatter = new HelpFormatter();
                    formatter.setWidth(100);
                    formatter.printHelp("java -jar powerauth-java-cmd.jar", options);
                    break;
            }

        } catch (ExecutionException e) {
            // silent, just let drop to "finally" clause...
        } catch (Exception e) {
            stepLogger.writeItem(
                    "Unknown error occurred",
                    e.getMessage(),
                    "ERROR",
                    e
            );
        } finally {
            stepLogger.close();
        }

    }

}
