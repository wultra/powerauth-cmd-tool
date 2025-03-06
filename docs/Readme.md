# PowerAuth Command-Line Tool Usage

This brief document serves as a documentation of the reference PowerAuth Client - a simple utility connecting to the standard RESTful API. The utility simulates a mobile device on desktop - you can use it for simple integration testing.

## Download PowerAuth Reference Client

You can download the latest `powerauth-java-cmd.jar` at the releases page:

- [PowerAuth Command-Line Tool Releases](https://github.com/wultra/powerauth-cmd-tool/releases)

## Supported Java Runtime Versions

The following Java runtime versions are supported:
- OpenJDK 17 (LTS release) or higher
- Oracle Java is not supported, please use OpenJDK.

Older Java versions are currently not supported due to migration to Spring Boot 3.

## Bouncy Castle Library Usage

The command-line tool application embeds the Bouncy Castle Java Security library. Configuration of the security provider in `java.security` file should not be required due to dynamic initialization of the provider, however the behaviour may vary per Java distribution.

## Deploying PowerAuth Backend Components 

See the [Server Side Tutorial](https://developers.wultra.com/products/mobile-security-suite/develop/tutorials/Authentication-in-Mobile-Apps/Server-Side-Tutorial) for information about deploying the backend components, how to initialize an activation and additional topics which provide required context in case you are new to PowerAuth.

The command-line tool usually communicates with the Enrollment server component, however it can be also used with [PowerAuth Web Flow](https://github.com/wultra/powerauth-webflow) or with your own backends in case you include the [PowerAuth RESTful Integration Libraries](https://github.com/wultra/powerauth-restful-integration). The command-line tool does not communicate with PowerAuth server directly.

## PowerAuth Client Config File

_Note: You must create this file before you can use the utility. Obtain the information from the PowerAuth Admin interface._

Client configuration file is required for the correct function of the command-line utility. It contains the same information that would be bundled inside a mobile app after download from the application marketplace. The file stores application name and mobile SDK configuration in the following format:

```json
{
  "applicationName": "PowerAuth Reference Client",
  "mobileSdkConfig": "ARCVs2uD4HXnu1uiMLjzv3jUEKhL+EbC7De2hP0CE4QZYMIBAUEEc7WjproYfURYdEDEx7OwSR0A5A+5HNGgUXx8F6eT3KOeIhcsw7tN5PoZN7m3sKutqmUPBrSFqtcDkmQxKTXzlA=="
}
```

You must obtain the values for this file from the PowerAuth Admin interface:

![PowerAuth Admin Preview](./images/pa_admin_application_detail.png)

Note: In case you use an older version of the PowerAuth server which does not contain the mobile SDK configuration parameter, configure the individual parameters in the following format:

```json
{
  "applicationName": "PowerAuth Reference Client",
  "applicationKey": "ivGlm/hl6rn9lSaD4qMgGw==",
  "applicationSecret": "bI5pNbDdAXWUr/UQY5+Tpg==",
  "masterPublicKey": "BO4+eqJPQTldjcV9G36dGiagsOHzgKgWz5uPuJKYwvIakbFmfWah1N4GXmBOS8aBEwQ+BcV04LL+OBBY0QS1bvg="
}
```

## PowerAuth Client Status File

_Note: You should not create this file yourself. The utility creates it for you._

This file is automatically created by the utility after you call the `create` method. It keeps the current PowerAuth Client activation status information. In other words, client status file contains everything that a mobile application would store after it was paired with the user account.

```json
{
  "activationId" : "cebb3ae6-f774-4b74-8020-f7b4da64de8f",
  "serverPublicKey" : "BKVanyqfLG2MxVwMt/LhmFliqPpHxVhtU3PEMG9FOIeJFkPAQjHpije029//S+bOprC4j6a8DMukxfoYkCFfLjU=",
  "counter" : 10,
  "ctrData" : "oJoq6ds50Z+udWcY6hnbig==",
  "encryptedDevicePrivateKey" : "HxRPkVVTM3QL+hecOY6cwQNvgNzvp2GbvvQ7cAOUXxzAk1dDaZVh1hd+2k18ZHn2",
  "signatureBiometryKey" : "4Kb+7AO49ZHOpA4vtYzZGA==",
  "signatureKnowledgeKeyEncrypted" : "i0LTZsWPlmRel0L7eg8U2w==",
  "signatureKnowledgeKeySalt" : "J/LULF2V/fqE7Dw7AZhlmA==",
  "signaturePossessionKey" : "jO89IxZs9bawvW3qlNQCzg==",
  "transportMasterKey" : "kOh0lamazBJgDLSIcZ/ZJw=="
}
```

## Specifying PowerAuth Protocol Version

Command-line tool supports following PowerAuth protocol versions:
- Version `3.3` (default)
- Version `3.2`
- Version `3.1`
- Version `3.0`

You can specify the version of protocol you want to use using parameter `version`. Both major and minor version needs to be specified for the command-line tool action, however the server stores only the major version in the database.
The version affects used cryptography, for example version `3` activations use an integrated ECIES scheme.

## Supported Use-Cases

### Create Activation

Use this method to create a new activation using an activation code.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "create" \
    --password "1234" \
    --activation-code "F3CCT-FNOUS-GEVJF-O3HMV"
```

Uses the `create` method to activate a PowerAuth Reference client by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/activation/create` hosted on root URL `http://localhost:8080/enrollment-server` with an activation code `F3CCT-FNOUS-GEVJF-O3HMV`. Reads and stores the client status from the `/tmp/pa_status.json` file. Uses master public key and application identifiers stored in the `/tmp/pamk.json` file. Stores the knowledge related derived key using a given password `1234`.

For backward compatibility, the tool also supports the `prepare` method as an alias to the `create` method, however this method is already deprecated. Usage of this method prints a deprecation warning.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to encrypt the knowledge related signature key._

_Note: In case auto-commit mode is not used (default), the activation needs to be committed on the server using [PowerAuth Admin application](https://github.com/wultra/powerauth-admin) or using the [PowerAuth server RESTful API](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-commitactivation)._

### Get Activation Status

Use this method to obtain information about existing activation.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "status"
```

Uses the `status` method to get the activation status for the activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/activation/status` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file.

### Remove the Activation

Use to remove the activation on the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "remove" \
    --password "1234"
```

Uses the `remove` method to remove activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/activation/remove` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge related signing key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

### Validate the Signature

Use this method to send signed GET or POST requests to given URL with provided data.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/pa/v3/signature/validate" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "sign" \
    --http-method "POST" \
    --resource-id "/pa/signature/validate" \
    --signature-type "possession_knowledge" \
    --data-file "/tmp/request.json" \
    --password "1234"
```

Uses the `sign` method to compute a signature for given data using an activation record associated with an activation ID stored in the status file `/tmp/pa_status.json`. Calls an authenticated endpoint `http://localhost:8080/enrollment-server/pa/v3/signature/validate` that is identified by an identifier `/pa/signature/validate` (by convention the same as the endpoint name after the main context except the version). The endpoint must be published by the application - see [Verify Signature](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#verify-signatures). Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Uses HTTP method `POST`, `possession_knowledge` signature type and takes the request data from a file `/tmp/request.json`. Unlocks the knowledge related signing key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

In case you are validating signature on requests that require authenticated session, use `--http-header` option:

You can use the `dry-run` parameter, in this case the step is stopped right after signing the request body and preparing appropriate headers.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/pa/v3/signature/validate" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "sign" \
    --http-method "POST" \
    --http-header Cookie="JSESSIONID=D0A047F9E8A9928386A5B34AB6343C30"
    --resource-id "/pa/signature/validate" \
    --signature-type "possession_knowledge" \
    --data-file "/tmp/request.json" \
    --password "1234"
```

_Note: The choice of signature version is determined by presence of `ctrData` in status file (present since version `3.0`)._

### Unlock the Secure Vault

Use this method to test secure vault unlocking.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "unlock" \
    --signature-type "possession_knowledge" \
    --password "1234" \
    --reason "NOT_SPECIFIED"
```

Uses the `unlock` method to unlock the secure vault for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/vault/unlock` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge related signing key using `1234` as a password. The reason why vault is being unlocked is `NOT_SPECIFIED`.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

### Create Token

Create a static token which can be used for repeated requests to data resources which support token based authentication.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "create-token" \
    --signature-type "possession_knowledge" \
    --password "1234"
```

Uses the `create-token` method to create a token for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/token/create` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the server public key, transport key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge related signing key using `1234` as a password. 

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

### Validate Token

Token validation may be performed against any endpoint using [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication).

For example, use the previously created token to retrieve a list of operations.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/api/auth/token/app/operation/list" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "validate-token" \
    --http-method "POST" \
    --data-file "/tmp/request.json" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

Uses the `validate-token` method for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling an endpoint `/api/auth/token/app/operation/list` hosted on root URL `http://localhost:8080/enrollment-server`.
Uses the application identifiers stored in the `/tmp/pamk.json` file.
The request data is taken from file `/tmp/request.json`.

You can use the `dry-run` parameter, in this case the step is stopped right after signing the request body and preparing appropriate headers.

### Remove Token

Remove a previously created token.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "remove-token" \
    --signature-type "possession_knowledge" \
    --password "1234" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2"
```

Uses the `remove-token` method to remove a previously created token for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v3/token/remove` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the application identifiers stored in the `/tmp/pamk.json` file to create the request signature. Unlocks the knowledge related signing key using `1234` as a password. 

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

### Custom Attributes for Activation

Use this method to create an activation using the custom identity attributes.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "create-custom" \
    --identity-file "/tmp/identity.json" \
    --custom-attributes-file "/tmp/custom-attributes.json" \
    --password "1234"
```

Uses the `create-custom` method to activate a PowerAuth Reference client by calling activation endpoint with identity attributes stored in `/tmp/identity.json` file and custom activation attributes stored in `/tmp/custom-attributes.json` file. Reads and stores the client status from the `/tmp/pa_status.json` file. Uses master public key and application identifiers stored in the `/tmp/pamk.json` file. Stores the knowledge related derived key using a given password `1234`.

There is a required format of both `identity.json` and `custom-attributes.json` files. The `custom-attributes.json` file may be any JSON file representing an object (at least, the file must contain `{}` string). The `identity.json` file must be a simple JSON object with identity attributes stored as string key-value, for example:

```json
{
    "username": "johndoe01",
    "password": "s3cR!7"
}
```

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to encrypt the knowledge related signature key._


### Send Encrypted Data to Server

Use this method to send encrypted data to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange" \
    --base-url "http://localhost:8080/enrollment-server" \
    --config-file "config.json" \
    --method "encrypt" \
    --data-file "request.json" \
    --scope "application"
```

Uses the `encrypt` method to encrypt data in `request.json` file using ECIES encryption. The encryption uses `application` scope, you can use the `activation` option to switch to activation scope. 
The encrypted data is sent to specified endpoint URL. The base URL is used for PowerAuth Standard RESTful API requests, e.g. to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data and return encrypted response back to the client. The cmd line tool receives the encrypted response from server, decrypts it and prints it into the command line.

### Send Signed and Encrypted Data to Server

Use this method to send signed and encrypted data to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange/v3/signed" \
    --base-url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "sign-encrypt" \
    --http-method "POST" \
    --resource-id "/exchange/v3/signed" \
    --signature-type "possession_knowledge" \
    --data-file "request.json" \
    --password "1234"
```

The data in `request.json` file is signed and encrypted using ECIES encryption. See chapter [Validate the Signature](#validate-the-signature) which describes signature parameters.
The encrypted data is sent to specified endpoint URL.  The base URL is used for PowerAuth Standard RESTful API requests, e.g. to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data, verify data signature and return encrypted response back to the client. The cmd line tool receives the encrypted response from server, decrypts it and prints it into the command line.

### Send Encrypted Data with Token Validation to Server

Use this method to send encrypted data with token validation to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange/v3/token" \
    --base-url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "token-encrypt" \
    --http-method "POST" \
    --data-file "request.json" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

The data in `request.json` file is encrypted using ECIES encryption and token authentication is computed.
The encrypted data is sent to specified endpoint URL. The base URL is used for PowerAuth Standard RESTful API requests, e.g. to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data, validate the token and return encrypted response back to the client. The cmd line tool receives the encrypted response from server, decrypts it and prints it into the command line.

### Start Upgrade

Use this method to start upgrade of a version `2` activation to version `3`.

```
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "start-upgrade"
```

The start upgrade request is sent to the server. The server response with generated hash based counter value `ctrData` which is later used for the first version `3.0` signature verification during commit upgrade.

### Commit Upgrade

Use this method to commit upgrade of a version `2` activation to version `3`.

```
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "commit-upgrade"
```

The commit upgrade request is sent to the server including a version `3.0` signature. The server verifies the request signature and commits the upgrade of activation to version `3`.

## Compute Offline Signature

Use this method to compute offline PowerAuth signature. 

```bash
java -jar powerauth-java-cmd.jar \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "compute-offline-signature" \
    --qr-code-data "c68dc57f-ee5f-497c-8c92-338439426e76\nApprove Login\nPlease confirm the login request.\nA2\nB\nETIK4iFz1E9u6vABKSbytg==\n1MEYCIQCnQqFFzS589auwdMRZ9Aq5qFxso21oxd2sng9Vp7gCUgIhAITaJ9L3fP2tov63mcIgU2e/37h9EXyAMhzrCXXDNJZE" \
    --password "1234"
```

The `qr-code-data` parameter is taken from QR code generated by PowerAuth RESTful services. Note that the QR code is signed, the signature is verified during offline signature computation. The method unlocks the knowledge related signing key using `1234` as a password.

The method does not execute any server calls due to its offline nature. The computed offline signature is used as an OTP and it is available from the output of the command in decimal format, e.g.: `"offlineSignature" : "99961544-80193814"`.

## Basic Usage

PowerAuth Reference Client is called as any Java application that is packaged as a JAR file and it uses following command-line arguments.

```
usage: java -jar powerauth-java-cmd.jar
 -a,--activation-code <arg>          In case a specified method is 'create', this field contains the
                                     activation key (a concatenation of a short activation ID and
                                     activation OTP).
 -b,--base-url <arg>                 Base URL of the PowerAuth Standard RESTful API.
 -A,--activation-otp <arg>           In case a specified method is 'create', this field contains
                                     additional activation OTP (PA server 0.24+)
 -c,--config-file <arg>              Specifies a path to the config file with Base64 encoded server
                                     master public key, application ID and application secret.
 -C,--custom-attributes-file <arg>   In case a specified method is 'create-custom', this field
                                     specifies the path to the file with custom attributes.
 -d,--data-file <arg>                In case a specified method is 'sign', 'sign-encrypt' or
                                     'token-encrypt', this field specifies a file with the input
                                     data to be signed and verified with the server, as specified in
                                     PowerAuth signature process or MAC token based authentication.
 -D,--device-info <arg>              Information about user device.
 -e,--endpoint <arg>                 Deprecated option, use the resource-id option instead.
 -E,--resource-id <arg>              In case a specified method is 'sign' or 'sign-encrypt', this
                                     field specifies a URI identifier, as specified in PowerAuth
                                     signature process.
 -h,--help                           Print this help manual.
 -H,--http-header <key=value>        Use provided HTTP header for communication
 -hs,--help-steps                    PowerAuth supported steps and versions.
 -hv,--help-versions                 PowerAuth supported versions and steps.
 -I,--identity-file <arg>            In case a specified method is 'create-custom', this field
                                     specifies the path to the file with identity attributes.
 -i,--invalidSsl                     Client may accept invalid SSL certificate in HTTPS
                                     communication.
 -l,--signature-type <arg>           In case a specified method is 'sign' or 'sign-encrypt', this
                                     field specifies a signature type, as specified in PowerAuth
                                     signature process.
 -m,--method <arg>                   What API method to call, available names are 'create',
                                     'status', 'remove', 'sign', 'unlock', 'create-custom',
                                     'create-token', 'validate-token', 'remove-token', 'encrypt',
                                     'sign-encrypt', 'token-encrypt', 'start-upgrade', and
                                     'commit-upgrade'.
 -o,--scope <arg>                    ECIES encryption scope: 'application' or 'activation'.
 -p,--password <arg>                 Password used for a knowledge related key encryption. If not
                                     specified, an interactive input is required.
 -P,--platform <arg>                 User device platform.
 -r,--reason <arg>                   Reason why vault is being unlocked.
 -s,--status-file <arg>              Path to the file with the activation status, serving as the
                                     data persistence.
 -S,--token-secret <arg>             Token secret (Base64 encoded bytes), in case of
                                     'token-validate' method.
 -t,--http-method <arg>              In case a specified method is 'sign', 'sign-encrypt' or
                                     'token-encrypt', this field specifies a HTTP method, as
                                     specified in PowerAuth signature process.
 -T,--token-id <arg>                 Token ID (UUID4), in case of 'token-validate' method.
 -u,--url <arg>                      URL used for the request.
 -v,--version <arg>                  PowerAuth protocol version.
 -y,--dry-run                        In case a specified method is 'sign', 'sign-encrypt',
                                     'validate-token' or 'token-encrypt' and this attribute is
                                     specified, the step is stopped right after signing the request
                                     body and preparing appropriate headers.
```

## Troubleshooting

**Everything should be deployed correctly but utility cannot connect.**

If you are using HTTPS, make sure you are using valid SSL certificate or that you use "-i" option.

**Error: JCE cannot authenticate the provider BC**

Please use a supported Java Runtime Version (OpenJDK 17 or higher, not Oracle Java).

See: https://github.com/wultra/powerauth-cmd-tool/issues/232#issuecomment-1730848437

## License

All PowerAuth command-line tool sources are licensed using Apache 2.0 license, you can use them with no restriction. Note that most of the PowerAuth backend components use the AGPL v3.0 license. If you are using PowerAuth, please let us know. We will be happy to share and promote your project.
