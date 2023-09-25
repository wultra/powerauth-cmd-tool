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

import io.getlime.security.powerauth.app.cmd.exception.ExecutionException;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.CmdLibApplication;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthStep;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.exception.PowerAuthCmdException;
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger;
import io.getlime.security.powerauth.lib.cmd.service.StepExecutionService;
import io.getlime.security.powerauth.lib.cmd.steps.StepProvider;
import io.getlime.security.powerauth.lib.cmd.steps.model.*;
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import io.getlime.security.powerauth.lib.cmd.util.ConfigurationUtil;
import io.getlime.security.powerauth.lib.cmd.util.FileUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import io.getlime.security.powerauth.lib.cmd.util.config.SdkConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.config.SdkConfigurationSerializer;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Command-line utility for testing PowerAuth implementation and for verification of
 * a correct system deployment.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 * @author Petr Dvorak, petr@wultra.com
 */
public class Application {

    /**
     * Application main
     * @param args Arguments, use --help to print expected arguments
     */
    @SuppressWarnings("unchecked")
    public static void main(String[] args) {

        ConfigurableApplicationContext appContext = new SpringApplicationBuilder(CmdLibApplication.class)
                .web(WebApplicationType.NONE)
                .run(args);

        StepExecutionService stepExecutionService = appContext.getBeanFactory().getBean(StepExecutionService.class);
        StepProvider stepProvider = appContext.getBeanFactory().getBean(StepProvider.class);
        StepLogger stepLogger = appContext.getBeanFactory().getBean(StepLogger.class);

        try {
            JSONObject clientConfigObject;

            // Add Bouncy Castle Security Provider
            Security.addProvider(new BouncyCastleProvider());

            // Options definition
            Options options = new Options();
            options.addOption("h", "help", false, "Print this help manual.");
            options.addOption("hs", "help-steps", false, "PowerAuth supported steps and versions.");
            options.addOption("hv", "help-versions", false, "PowerAuth supported versions and steps.");
            options.addOption("u", "url", true, "Base URL of the PowerAuth Standard RESTful API.");
            options.addOption("m", "method", true, "What API method to call, available names are 'create', 'status', 'remove', 'sign', 'unlock', 'create-custom', 'create-token', 'validate-token', 'remove-token', 'encrypt', 'sign-encrypt', 'token-encrypt', 'start-upgrade', 'commit-upgrade', 'create-recovery' and 'confirm-recovery-code'.");
            options.addOption("c", "config-file", true, "Specifies a path to the config file with Base64 encoded server master public key, application ID and application secret.");
            options.addOption("s", "status-file", true, "Path to the file with the activation status, serving as the data persistence.");
            options.addOption("a", "activation-code", true, "In case a specified method is 'create', this field contains the activation key (a concatenation of a short activation ID and activation OTP).");
            options.addOption("A", "activation-otp", true, "In case a specified method is 'create', this field contains additional activation OTP (PA server 0.24+)");
            options.addOption("t", "http-method", true, "In case a specified method is 'sign', 'sign-encrypt' or 'token-encrypt', this field specifies a HTTP method, as specified in PowerAuth signature process.");
            options.addOption("e", "endpoint", true, "Deprecated option, use the resource-id option instead.");
            options.addOption("E", "resource-id", true, "In case a specified method is 'sign' or 'sign-encrypt', this field specifies a URI identifier, as specified in PowerAuth signature process.");
            options.addOption("l", "signature-type", true, "In case a specified method is 'sign' or 'sign-encrypt', this field specifies a signature type, as specified in PowerAuth signature process.");
            options.addOption("d", "data-file", true, "In case a specified method is 'sign', 'sign-encrypt' or 'token-encrypt', this field specifies a file with the input data to be signed and verified with the server, as specified in PowerAuth signature process or MAC token based authentication.");
            options.addOption("y", "dry-run", false, "In case a specified method is 'sign', 'sign-encrypt', 'validate-token' or 'token-encrypt' and this attribute is specified, the step is stopped right after signing the request body and preparing appropriate headers.");
            options.addOption("p", "password", true, "Password used for a knowledge related key encryption. If not specified, an interactive input is required.");
            options.addOption("I", "identity-file", true, "In case a specified method is 'create-custom', this field specifies the path to the file with identity attributes.");
            options.addOption("C", "custom-attributes-file", true, "In case a specified method is 'create-custom', this field specifies the path to the file with custom attributes.");
            options.addOption("i", "invalidSsl", false, "Client may accept invalid SSL certificate in HTTPS communication.");
            options.addOption("T", "token-id", true, "Token ID (UUID4), in case of 'token-validate' method.");
            options.addOption("S", "token-secret", true, "Token secret (Base64 encoded bytes), in case of 'token-validate' method.");
            options.addOption("r", "reason", true, "Reason why vault is being unlocked.");
            options.addOption("o", "scope", true, "ECIES encryption scope: 'application' or 'activation'.");
            options.addOption("R", "recovery-code", true, "Recovery code to be confirmed.");
            options.addOption("P", "platform", true, "User device platform.");
            options.addOption("D", "device-info", true, "Information about user device.");
            options.addOption("q", "qr-code-data", true, "Data for offline signature encoded in QR code.");
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

            if (cmd.hasOption("hs")) {
                printPowerAuthStepsHelp(stepProvider);
                return;
            }

            if (cmd.hasOption("hv")) {
                printPowerAuthVersionsHelp(stepProvider);
                return;
            }

            // Check if help was invoked
            if (cmd.hasOption("h") || !cmd.hasOption("m")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.setWidth(100);
                formatter.printHelp("java -jar powerauth-java-cmd.jar", options);
                return;
            }

            if (cmd.hasOption("e") || cmd.hasOption("endpoint")) {
                System.err.println("The 'e' (endpoint) option is deprecated, use the 'E' (resource-id) option instead");
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
                RestClientFactory.setAcceptInvalidSslCertificate(true);
            }

            String platform;
            if (cmd.hasOption("P")) {
                platform = cmd.getOptionValue("P");
            } else {
                platform = "unknown";
            }

            String deviceInfo;
            if (cmd.hasOption("D")) {
                deviceInfo = cmd.getOptionValue("D");
            } else {
                deviceInfo = "cmd-tool";
            }

            String qrCodeData = null;
            if (cmd.hasOption("q")) {
                qrCodeData = cmd.getOptionValue("q");
            }

            // Read values
            String method = cmd.getOptionValue("m");
            String uriString = cmd.getOptionValue("u");
            String statusFileName = cmd.getOptionValue("s");
            String configFileName = cmd.getOptionValue("c");
            String reason = cmd.getOptionValue("r");
            String versionValue = cmd.getOptionValue("v", PowerAuthVersion.DEFAULT.value());
            PowerAuthVersion version = PowerAuthVersion.fromValue(versionValue);

            // Read config file
            Map<String,String> configAttributes =
                    FileUtil.readDataFromFile(stepLogger, configFileName, HashMap.class, "config", "config file");
            clientConfigObject = new JSONObject(configAttributes);

            // Read master public key
            final String mobileSdkConfig = ConfigurationUtil.getMobileSdkConfig(clientConfigObject);
            final String applicationKey;
            final String applicationSecret;
            final PublicKey masterPublicKey;
            if (mobileSdkConfig != null) {
                // Extract simplified mobile SDK configuration
                final SdkConfiguration config = SdkConfigurationSerializer.deserialize(mobileSdkConfig);
                if (config == null) {
                    stepLogger.writeError("invalid-sdk-config", "Invalid Mobile SDK Config", "Mobile SDK Config is not valid");
                    stepLogger.writeDoneFailed("sdk-config-failed");
                    System.exit(1);
                }
                applicationKey = config.appKeyBase64();
                applicationSecret = config.appSecretBase64();
                masterPublicKey = ConfigurationUtil.getMasterPublicKey(config, stepLogger);
            } else {
                // Fallback to traditional mobile SDK configuration
                applicationKey = ConfigurationUtil.getApplicationKey(clientConfigObject);
                applicationSecret = ConfigurationUtil.getApplicationSecret(clientConfigObject);
                masterPublicKey = ConfigurationUtil.getMasterPublicKey(clientConfigObject, stepLogger);
            }

            // Read current activation state from the activation state file or create an empty state
            ResultStatusObject resultStatusObject;
            if (statusFileName != null && Files.isReadable(Paths.get(statusFileName))) {
                byte[] statusFileBytes = Files.readAllBytes(Paths.get(statusFileName));
                resultStatusObject = RestClientConfiguration.defaultMapper().readValue(new String(statusFileBytes, StandardCharsets.UTF_8), ResultStatusObject.class);
            } else {
                resultStatusObject = new ResultStatusObject();
            }

            PowerAuthStep powerAuthStep;
            try {
                powerAuthStep = PowerAuthStep.fromMethod(method);
            } catch (IllegalStateException e) {
                System.err.println("Not recognized PowerAuth step/method: " + method);
                printPowerAuthStepsHelp(stepProvider);
                return;
            }

            // Execute the code for given methods
            switch (powerAuthStep) {
                case TOKEN_CREATE -> {

                    CreateTokenStepModel model = new CreateTokenStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case TOKEN_VALIDATE -> {

                    VerifyTokenStepModel model = new VerifyTokenStepModel();
                    model.setTokenId(cmd.getOptionValue("T"));
                    model.setTokenSecret(cmd.getOptionValue("S"));
                    model.setHeaders(httpHeaders);
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setVersion(version);
                    model.setDryRun(cmd.hasOption("dry-run"));

                    // Read the file with request data
                    String dataFileName = cmd.getOptionValue("d");
                    final byte[] dataFileBytes = FileUtil.readFileBytes(stepLogger, dataFileName, "request-data", "Request data file");
                    model.setData(dataFileBytes);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case TOKEN_REMOVE -> {
                    RemoveTokenStepModel model = new RemoveTokenStepModel();
                    model.setTokenId(cmd.getOptionValue("T"));
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ACTIVATION_CREATE, ACTIVATION_PREPARE -> {
                    if (powerAuthStep.equals(PowerAuthStep.ACTIVATION_PREPARE)) {
                        System.err.println("The 'prepare' step name is deprecated, use the 'create' step name instead");
                        powerAuthStep = PowerAuthStep.ACTIVATION_CREATE;
                    }

                    PrepareActivationStepModel model = new PrepareActivationStepModel();
                    model.setActivationCode(cmd.getOptionValue("a"));
                    model.setAdditionalActivationOtp(cmd.getOptionValue("A"));
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setPlatform(platform);
                    model.setDeviceInfo(deviceInfo);
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ACTIVATION_STATUS -> {

                    GetStatusStepModel model = new GetStatusStepModel();
                    model.setHeaders(httpHeaders);
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ACTIVATION_REMOVE -> {

                    RemoveStepModel model = new RemoveStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case SIGNATURE_VERIFY -> {

                    VerifySignatureStepModel model = new VerifySignatureStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResourceId(cmd.getOptionValue("E", cmd.getOptionValue("e")));
                    model.setResultStatus(resultStatusObject);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);
                    model.setDryRun(cmd.hasOption("dry-run"));

                    // Read the file with request data
                    String dataFileName = cmd.getOptionValue("d");
                    final byte[] dataFileBytes = FileUtil.readFileBytes(stepLogger, dataFileName, "request-data", "Request data file");
                    model.setData(dataFileBytes);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case VAULT_UNLOCK -> {

                    VaultUnlockStepModel model = new VaultUnlockStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setStatusFileName(statusFileName);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setUriString(uriString);
                    model.setReason(reason);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ACTIVATION_CREATE_CUSTOM -> {

                    String identityAttributesFileName = cmd.getOptionValue("I");
                    Map<String, String> identityAttributes =
                            FileUtil.readDataFromFile(stepLogger, identityAttributesFileName, HashMap.class, "identity-attributes", "identity attributes");

                    String customAttributesFileName = cmd.getOptionValue("C");
                    Map<String, Object> customAttributes =
                            FileUtil.readDataFromFile(stepLogger, customAttributesFileName, HashMap.class, "custom-attributes", "custom attributes");

                    CreateActivationStepModel model = new CreateActivationStepModel();
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setPlatform(platform);
                    model.setDeviceInfo(deviceInfo);
                    model.setActivationOtp(cmd.getOptionValue("a"));
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setCustomAttributes(customAttributes);
                    model.setHeaders(httpHeaders);
                    model.setIdentityAttributes(identityAttributes);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ENCRYPT -> {
                    EncryptStepModel model = new EncryptStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setDryRun(cmd.hasOption("dry-run"));
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setResultStatus(resultStatusObject);
                    model.setScope(cmd.getOptionValue("o"));
                    model.setUriString(uriString);
                    model.setVersion(version);

                    // Read the file with request data
                    String dataFileName = cmd.getOptionValue("d");
                    final byte[] dataFileBytes = FileUtil.readFileBytes(stepLogger, dataFileName, "request-data", "Request data file");
                    model.setData(dataFileBytes);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case SIGN_ENCRYPT -> {
                    VerifySignatureStepModel model = new VerifySignatureStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResourceId(cmd.getOptionValue("E", cmd.getOptionValue("e")));
                    model.setResultStatus(resultStatusObject);
                    model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(cmd.getOptionValue("l")));
                    model.setStatusFileName(statusFileName);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    // Read the file with request data
                    String dataFileName = cmd.getOptionValue("d");
                    final byte[] dataFileBytes = FileUtil.readFileBytes(stepLogger, dataFileName, "request-data", "Request data file");
                    model.setData(dataFileBytes);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case TOKEN_ENCRYPT -> {
                    TokenAndEncryptStepModel model = new TokenAndEncryptStepModel();
                    model.setTokenId(cmd.getOptionValue("T"));
                    model.setTokenSecret(cmd.getOptionValue("S"));
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHttpMethod(cmd.getOptionValue("t"));
                    model.setDryRun(cmd.hasOption("dry-run"));
                    model.setHeaders(httpHeaders);
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    // Read the file with request data
                    String dataFileName = cmd.getOptionValue("d");
                    final byte[] dataFileBytes = FileUtil.readFileBytes(stepLogger, dataFileName, "request-data", "Request data file");
                    model.setData(dataFileBytes);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case UPGRADE_START -> {
                    StartUpgradeStepModel model = new StartUpgradeStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setStatusFileName(statusFileName);
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case UPGRADE_COMMIT -> {
                    CommitUpgradeStepModel model = new CommitUpgradeStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setStatusFileName(statusFileName);
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case ACTIVATION_RECOVERY -> {
                    String identityAttributesFileName = cmd.getOptionValue("I");
                    Map<String, String> identityAttributes =
                            FileUtil.readDataFromFile(stepLogger, identityAttributesFileName, HashMap.class, "identity-attributes", "identity attributes");

                    String customAttributesFileName = cmd.getOptionValue("C");
                    Map<String, Object> customAttributes =
                            FileUtil.readDataFromFile(stepLogger, customAttributesFileName, HashMap.class, "custom-attributes", "custom attributes");

                    ActivationRecoveryStepModel model = new ActivationRecoveryStepModel();
                    model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject));
                    model.setPlatform(platform);
                    model.setDeviceInfo(deviceInfo);
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setIdentityAttributes(identityAttributes);
                    model.setCustomAttributes(customAttributes);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case RECOVERY_CONFIRM -> {

                    ConfirmRecoveryCodeStepModel model = new ConfirmRecoveryCodeStepModel();
                    model.setApplicationKey(applicationKey);
                    model.setApplicationSecret(applicationSecret);
                    model.setHeaders(httpHeaders);
                    model.setMasterPublicKey(masterPublicKey);
                    model.setStatusFileName(statusFileName);
                    model.setRecoveryCode(cmd.getOptionValue("R"));
                    model.setResultStatus(resultStatusObject);
                    model.setUriString(uriString);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                case SIGNATURE_OFFLINE_COMPUTE -> {

                    ComputeOfflineSignatureStepModel model = new ComputeOfflineSignatureStepModel();
                    model.setStatusFileName(statusFileName);
                    model.setQrCodeData(qrCodeData);
                    model.setPassword(cmd.getOptionValue("p"));
                    model.setResultStatus(resultStatusObject);
                    model.setVersion(version);

                    stepExecutionService.execute(powerAuthStep, version, model);
                }
                default -> {
                    System.err.println("Not recognized PowerAuth step: " + powerAuthStep);
                    printPowerAuthStepsHelp(stepProvider);
                }
            }

        } catch (ExecutionException | PowerAuthCmdException e) {
            // silent, just let drop to "finally" clause...
        } catch (Exception e) {
            stepLogger.writeItem(
                    "generic-error-generic",
                    "Unknown error occurred",
                    e.getMessage(),
                    "ERROR",
                    e
            );
        } finally {
            stepLogger.close();
        }

    }

    private static void printPowerAuthStepsHelp(StepProvider stepProvider) {
        System.out.println("Available PowerAuth steps and supported versions.\n");
        System.out.printf("%-22s%s%n", "PowerAuth step", "Supported versions");
        for (PowerAuthStep step : PowerAuthStep.values()) {
            List<String> versions = stepProvider.getSupportedVersions(step)
                    .stream()
                    .map(PowerAuthVersion::value)
                    .sorted()
                    .collect(Collectors.toList());
            System.out.printf("%-22s%s%n", step.alias(), versions.isEmpty() ? "deprecated support" : versions);
        }
    }

    private static void printPowerAuthVersionsHelp(StepProvider stepProvider) {
        System.out.println("Supported PowerAuth versions and available steps.\n");
        System.out.printf("%-20s%s%n", "PowerAuth version", "Available steps");
        for (PowerAuthVersion version : PowerAuthVersion.values()) {
            List<String> steps = stepProvider.getAvailableSteps(version)
                    .stream()
                    .map(PowerAuthStep::alias)
                    .sorted()
                    .collect(Collectors.toList());
            System.out.printf("%-20s%s%n", version.value(), steps);
        }
    }

}
