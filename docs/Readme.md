# PowerAuth Command-Line Tool Usage

This brief document serves as documentation of the reference PowerAuth Client, a command line utility connecting to the standard RESTful API. The utility simulates a mobile device on desktop, and you can use it for integration testing.

## Download PowerAuth Reference Client

You can download the latest `powerauth-java-cmd.jar` at the releases page:

- [PowerAuth Command-Line Tool Releases](https://github.com/wultra/powerauth-cmd-tool/releases)

## Supported Java Runtime Versions

The following Java runtime versions are supported:
- OpenJDK 17 (LTS release)
- OpenJDK 21 (LTS release)

You can obtain the JDK from https://adoptium.net

Older Java versions are currently not supported due to migration to Spring Boot 3.

## Bouncy Castle Library Usage

The command-line tool application embeds the Bouncy Castle Java Security library. No extra cryptography library configuration is required.

## Deploying PowerAuth Backend Components

See the [Server Side Tutorial](https://developers.wultra.com/tutorials/posts/Mobile-First-Authentication/Server-Side-Tutorial-Deployment) for information about deploying the backend components, how to initialize an activation and additional topics which provide required context in case you are new to PowerAuth.

The command-line tool usually communicates with the Enrollment server component; however, it can be also used with your own backends in case you include the [PowerAuth RESTful Integration Libraries](https://github.com/wultra/powerauth-restful-integration). The command-line tool does not communicate with the PowerAuth server directly.

## PowerAuth Client Config File

_Note: You must create this file before you can use the utility. Obtain the information from the PowerAuth Admin interface._

Client configuration file is required for the correct function of the command-line utility. It contains the same information that would be bundled inside a mobile app after download from the application marketplace. The file stores application name and mobile SDK configuration in the following format:

```json
{
  "applicationName": "PowerAuth Reference Client",
  "mobileSdkConfig": "ARDg133BAu8SVlX/7KGe9Wn1ENi+HRDCExFqhyr1zVxoqyAEAUEETZASzdJECB/ZaU0yYonk..."
}
```

You can obtain the `mobileSdkConfig` value for this file from the PowerAuth Server REST API: 

```bash
curl --request POST \
--url https://[host]:[port]/powerauth-java-server/rest/v4/application/detail \
--header 'Content-Type: application/json' \
--data '{
  "requestObject": {
    "applicationId": "your_app_id"
  }
}'
```

## PowerAuth Client Status File

_Note: You should not create this file yourself. The utility creates it for you._

This file is automatically created by the utility after you call the `create` method. It keeps the current PowerAuth Client activation status information. In other words, the client status file contains everything that a mobile application would store after it was paired with the user account.

```json
{
  "version" : 4,
  "statusBlobMacKey" : "HTZU2qoifAgkPybdCYB5XHYz/z0w/oebgLUV+GzbU1U=",
  "ecServerPublicKey" : "BEdCDJIzpKfDm33zIGVWU/5sHoxwc0KpXxd8HNrHjwr7J+9Pdnp2lF1...",
  "pqcServerPublicKey" : "MIIKMjALBglghkgBZQMEAxMDggohAOvq3IvqT0z8DZrMr4tKAxGoxt...",
  "ecDevicePublicKey" : "BCCTidJfA2/LZCarFU5ZdZtFGhgNYFZOMxSpRV2DxJkcKBfUoICRSFt...",
  "pqcDevicePublicKey" : "MIIKMjALBglghkgBZQMEAxMDggohANiXJ1ONU9pzzFhmhxS9SZMd/5...",
  "biometryFactorKey" : "Y6wEa1NlK/LcptQkXf3IdxIaYZb6yJeB+OlZ0QkW8R0=",
  "knowledgeFactorKeySalt" : "AVKqkUaehNWAMLCpE0VvMQ==",
  "possessionFactorKey" : "9zKqOOYRlociI5wn04HM+mFNya8jN3/QwCAOkm0LRY0=",
  "sharedInfo2Key" : "29A20XMjFjDzRHTc5z8YDKUtvnMRSUP7XNqxZV1jPxI=",
  "activationId" : "c0b0a464-bcc8-4560-b9bd-752375466bed",
  "sharedSecretAlgorithm" : "EC_P384_ML_L5",
  "ctrData" : "gxgHs3K+B63pfbXnZWBoab/cL3VtS04CNsp1ADxJvmU=",
  "counter" : 0,
  "temporaryKeyActSignRequestKey" : "rrmIyYs4CSuhMZpFY895jd3eCRSC9WwGKuKm/wDSPFk=",
  "encryptedEcDevicePrivateKey" : "EudiUGjVdJShE7B92ABlnjNDTlW8uGu3Sc6hiSnhW/7vY...",
  "encryptedPqcDevicePrivateKey" : "vPlPyA6hCELuq8LAVu3CjCUhfTP7ct+6e2Ky3lzPfws2...",
  "knowledgeFactorKeyEncrypted" : "ne/+HhqwvHINF863Qc3H7Z49L0/77aT0srWVSPNFiWc="
}
```

## Specifying PowerAuth Protocol Version

Command-line tool supports following PowerAuth protocol versions:
- Version `4.0` (default)
- Version `3.3`
- Version `3.2`
- Version `3.1`
- Version `3.0`

You can specify the version of protocol you want to use using parameter `version`. Both major and minor versions need to be specified for the command-line tool action, however the server stores only the major version in the database.

The version affects used cryptography, for example, version `4` activations use an AEAD encryption scheme, and version `3` uses an ECIES encryption scheme.

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
    --version "4.0" \
    --algorithm "EC_P384_ML_L5" \    
    --activation-code "F3CCT-FNOUS-GEVJF-O3HMV"
```

Uses the `create` method to activate a PowerAuth Reference client by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/activation/create` hosted on root URL `http://localhost:8080/enrollment-server` with an activation code `F3CCT-FNOUS-GEVJF-O3HMV`. Reads and stores the client status from the `/tmp/pa_status.json` file. Uses master public key and application identifiers stored in the `/tmp/pamk.json` file. Stores the knowledge-related derived key using a given password `1234`. The cryptography protocol version is `4.0` and the algorithm used during activation is `EC_P384_ML_L5`.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to encrypt the knowledge-related authentication key._

_Note: In case auto-commit mode is not used (default), the activation needs to be committed on the server using the [PowerAuth Server RESTful API](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods-V4.md#method-commitactivation)._

### Get Activation Status

Use this method to obtain information about existing activation.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --version "4.0" \
    --method "status"
```

Uses the `status` method to get the activation status for the activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/activation/status` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. The cryptography protocol version is `4.0`.

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

Uses the `remove` method to remove activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/activation/remove` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Confirm the Activation

Use to confirm the activation on the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "pamk.json" \
    --method "confirm" \
    --password "1234" \
    --enable-biometry \
    --version "4.0"
```

Uses the `confirm` method to confirm activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/activation/confirm` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password. The biometric factor is enabled on server during this step.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Change Password for the Knowledge Factor

Use to change the password for the knowledge factor.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "pamk.json" \
    --auth-code-type "possession_knowledge" \
    --version "4.0" \
    --password "1234" \
    --password-new "1235" \
    --method "change-password"
```

Uses the `change-password` method to change the password for the knowledge factor for the activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/password/change` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password. The new password is `1235`.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Set Up Biometric Factor

Use to set up a biometric factor.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "pamk.json" \
    --auth-code-type "possession_knowledge" \
    --version "4.0" \
    --password "1234" \
    --method "setup-biometry"
```

Uses the `setup-biometry` method to set up the biometric factor for the activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/biometry/add` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Remove Biometric Factor

Use to remove the biometric factor.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "pamk.json" \
    --auth-code-type "possession" \
    --version "4.0" \
    --method "remove-biometry"
```

Uses the `remove-biometry` method to remove up the biometric factor for the activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/biometry/add` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file.

### Validate the Authentication Code

Use this method to send authenticated GET or POST requests to given URL with provided data.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/pa/v4/auth/validate" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "authenticate" \
    --http-method "POST" \
    --resource-id "/pa/auth/validate" \
    --auth-code-type "possession_knowledge" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --password "1234"
```

Uses the `authenticate` method to compute an authentication code for given data using an activation record associated with an activation ID stored in the status file `/tmp/pa_status.json`. Calls an authenticated endpoint `http://localhost:8080/enrollment-server/pa/v4/auth/validate` that is identified by an identifier `/pa/auth/validate` (by convention the same as the endpoint name after the main context except the version). The endpoint must be published by the application, see [Verify Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#verify-authentication-codes). Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Uses HTTP method `POST`, `possession_knowledge` authentication code type and takes the request data from a file `/tmp/request.json`. Unlocks the knowledge-related authentication key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

In case you are validating authentication code on requests that require authenticated session, use `--http-header` option:

You can use the `dry-run` parameter, in this case the step is stopped right after authenticating the request body and preparing appropriate headers.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/pa/v4/auth/validate" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "authenticate" \
    --http-method "POST" \
    --http-header Cookie="JSESSIONID=D0A047F9E8A9928386A5B34AB6343C30"
    --resource-id "/pa/auth/validate" \
    --auth-code-type "possession_knowledge" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --password "1234"
```

### Unlock the Secure Vault

Use this method to test secure vault unlock.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "unlock" \
    --auth-code-type "possession_knowledge" \
    --password "1234" \
    --version "4.0" \
    --key-identifier "KEK_DEVICE_PRIVATE"
    --reason "NOT_SPECIFIED"
```

Uses the `unlock` method to unlock the secure vault for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/vault/unlock` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password. The reason why vault is being unlocked is `NOT_SPECIFIED`. The key identifier is `KEK_DEVICE_PRIVATE`.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Sign Data Using Asymmetric Algorithm

Use this method to test obtaining the device private key and signing the data.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "sign-asymmetric" \
    --auth-code-type "possession_knowledge" \
    --version "4.0" \
    --password "1234" \
    --data-file "/tmp/request.json"
```

Uses the `sign-asymmetric` method to unlock the secure vault for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/vault/unlock` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the master public key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password. The reason why vault is being unlocked is `SIGN_DATA`. The key identifier used for unlocking the vault is `KEK_DEVICE_PRIVATE`. 

The unlocked device private key is then used for signing data using an asymmetric data signature algorithm. The asymmetric signature algorithm depends on the cryptography version.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Create Token

Create a static token which can be used for repeated requests to data resources which support token based authentication.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "create-token" \
    --auth-code-type "possession_knowledge" \
    --version "4.0" \
    --password "1234"
```

Uses the `create-token` method to create a token for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/token/create` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the server public key, transport key and application identifiers stored in the `/tmp/pamk.json` file. Unlocks the knowledge-related authentication key using `1234` as a password. 

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

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
    --version "4.0" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

Uses the `validate-token` method for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling an endpoint `/api/auth/token/app/operation/list` hosted on root URL `http://localhost:8080/enrollment-server`.
Uses the application identifiers stored in the `/tmp/pamk.json` file.
The request data is taken from file `/tmp/request.json`.

You can use the `dry-run` parameter, in this case the step is stopped right after authenticating and preparing appropriate headers.

### Remove Token

Remove a previously created token.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "remove-token" \
    --auth-code-type "possession_knowledge" \
    --version "4.0" \
    --password "1234" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2"
```

Uses the `remove-token` method to remove a previously created token for an activation with activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth Standard RESTful API endpoint `/pa/v4/token/remove` hosted on root URL `http://localhost:8080/enrollment-server`. Uses the application identifiers stored in the `/tmp/pamk.json` file to create the request authentication code. Unlocks the knowledge-related authentication key using `1234` as a password. 

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge-related authentication key._

### Get Pending Operation

The list of pending transaction can be obtained in the operation endpoint using [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication). This used the method `validate-token`. For method detail check the Validate Token above.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/api/auth/token/app/operation/list" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "validate-token" \
    --http-method "POST" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

### Claim Non-Personalized Operation

A non-personalized operation can be claimed on the server using [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication). This uses the `validate-token` method; see [Validate Token](#validate-token) above for details.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/api/auth/token/app/operation/detail/claim" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "validate-token" \
    --http-method "POST" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

The example of the request.json:

```json
{
  "requestObject": {
    "id": "ID of the operation to be claimed"
  }
}
```

### Get Operation Detail

An  operation can be obtained from the server using [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication). This used the method `validate-token`. For method detail check the Validate Token above.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/api/auth/token/app/operation/detail" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "validate-token" \
    --http-method "POST" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

The example of the request.json:

```json
{
    "requestObject": {
    "id": "id of the operation"
  }
}
```

### Approve Operation

An operation can be approved on the server using the `authenticate` method (see [Validate the Authentication Code](#validate-the-authentication-code)). The `data` field from the Get Operation Detail / Claim response must be included in the request.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/api/auth/token/app/operation/authorize" \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "authenticate" \
    --http-method "POST" \
    --resource-id "/operation/authorize" \
    --auth-code-type "possession_knowledge" \
    --data-file "/tmp/request.json" \
    --version "4.0" \
    --password "1234"
```

The example of the request.json:

```json
{
  "requestObject": {
    "id": "id of operation to be approved",
    "data": "operation data that has been signed - has to correspond with the operation data returned in detail or claim API  "
  }
}
```

The parameter `auth-code-type` must correspond to expected factors required to approve the operation.

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
    --version "4.0" \
    --password "1234"
```

Uses the `create-custom` method to activate a PowerAuth Reference client by calling activation endpoint with identity attributes stored in `/tmp/identity.json` file and custom activation attributes stored in `/tmp/custom-attributes.json` file. Reads and stores the client status from the `/tmp/pa_status.json` file. Uses master public key and application identifiers stored in the `/tmp/pamk.json` file. Stores the knowledge-related derived key using a given password `1234`.

There is a required format of both `identity.json` and `custom-attributes.json` files. The `custom-attributes.json` file may be any JSON file representing an object (at least, the file must contain `{}` string). The `identity.json` file must be a simple JSON object with identity attributes stored as string key-value, for example:

```json
{
    "username": "johndoe01",
    "password": "s3cR!7"
}
```

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to encrypt the knowledge-related authentication key._

### Send Encrypted Data to Server

Use this method to send encrypted data to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange" \
    --base-url "http://localhost:8080/enrollment-server" \
    --config-file "config.json" \
    --method "encrypt" \
    --version "4.0" \
    --data-file "request.json" \
    --scope "application"
```

Uses the `encrypt` method to encrypt data in `request.json` file using ECIES encryption. The encryption uses `application` scope, you can use the `activation` option to switch to activation scope. 
The encrypted data is sent to a specified endpoint URL. The base URL is used for PowerAuth Standard RESTful API requests, e.g., to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data and return an encrypted response back to the client. The cmd line tool receives the encrypted response from the server, decrypts it and prints it into the command line.

### Send Authenticated and Encrypted Data to Server

Use this method to send authenticated and encrypted data to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange/v4/signed" \
    --base-url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "authenticate-encrypt" \
    --http-method "POST" \
    --version "4.0" \
    --resource-id "/exchange/v4/signed" \
    --auth-code-type "possession_knowledge" \
    --data-file "request.json" \
    --password "1234"
```

The data in `request.json` file is authenticated and encrypted using AEAD encryption. See chapter [Validate the Authentication Code](#validate-the-authentication-code) which describes authentication parameters.
The encrypted data is sent to a specified endpoint URL.  The base URL is used for PowerAuth Standard RESTful API requests, e.g., to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data, verify data authentication and return encrypted response back to the client. The cmd line tool receives the encrypted response from the server, decrypts it and prints it into the command line.

### Send Encrypted Data with Token Validation to Server

Use this method to send encrypted data with token validation to the server.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server/exchange/v4/token" \
    --base-url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "token-encrypt" \
    --http-method "POST" \
    --version "4.0" \
    --data-file "request.json" \
    --token-id "66b8b981-a89d-4fc2-bd49-1c05f937a6f2" \
    --token-secret "xfb1NUXAPbvDZK8qyNVGyw=="
```

The data in `request.json` file is encrypted using ECIES encryption and token authentication is computed.
The encrypted data is sent to a specified endpoint URL. The base URL is used for PowerAuth Standard RESTful API requests, e.g., to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data, validate the token and return the encrypted response back to the client. The cmd line tool receives the encrypted response from the server, decrypts it and prints it into the command line.

### Start Upgrade

Use this method to start upgrade of a version `3` activation to version `4`.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "start-upgrade" \
    --password "1234" \
    --version "4.0" \
    --algorithm "EC_P384_ML_L5"    
```

The start upgrade request is sent to the server. The server response contains a shared secret response, server public keys and generated hash based counter value `ctrData` which is later used for the first version `4.0` authentication code verification during upgrade confirmation.

### Confirm Upgrade

Use this method to confirm upgrade of a version `3` activation to version `4`.

```bash
java -jar powerauth-java-cmd.jar \
    --url "http://localhost:8080/enrollment-server" \
    --status-file "pa_status.json" \
    --config-file "config.json" \
    --method "confirm-upgrade" \
    --version "4.0"
```

The confirm upgrade request is sent to the server including a version `4.0` authentication code. The server verifies the request authentication code and confirms the upgrade of activation to version `4`.

## Compute Offline Authentication Code

Use this method to compute offline PowerAuth authentication code. 

```bash
java -jar powerauth-java-cmd.jar \
    --status-file "/tmp/pa_status.json" \
    --config-file "/tmp/pamk.json" \
    --method "compute-offline-auth-code" \
    --qr-code-data "A2\n4bG7ZvoG6UfkF29iwfWXiA==\n2WVNRWpbnQOmzVwWwBe8bMsQIs8zKiy/oRYH7TOFE2lQ=" \
    --version "4.0" \
    --password "1234"
```

The `qr-code-data` parameter is taken from QR code generated by PowerAuth RESTful services. Note that the QR code is signed; the signature is verified during offline authentication code computation. The method unlocks the knowledge-related authentication key using `1234` as a password.

The method does not execute any server calls due to its offline nature. The computed offline authentication code is used as an OTP, and it is available from the output of the command in decimal format, e.g.: `99961544-80193814`.

## Basic Usage

PowerAuth Reference Client is called as any Java application that is packaged as a JAR file, and it uses the following command-line arguments.

```
usage: java -jar powerauth-java-cmd.jar
 -a,--activation-code <arg>          In case the specified method is 'create', this field contains
                                     the activation key (a concatenation of a short activation ID
                                     and activation OTP).
 -A,--activation-otp <arg>           In case the specified method is 'create', this field contains
                                     additional activation OTP (PA server 0.24+)
 -b,--base-url <arg>                 Base URL of the PowerAuth Standard RESTful API.
 -c,--config-file <arg>              Specifies a path to the config file with Base64 encoded server
                                     master public key, application ID and application secret.
 -C,--custom-attributes-file <arg>   In case the specified method is 'create-custom', this field
                                     specifies the path to the file with custom attributes.
 -d,--data-file <arg>                In case the specified method is 'authenticate',
                                     'authenticate-encrypt' or 'token-encrypt', this field specifies
                                     a file with the input data to be authenticated and verified
                                     with the server, as specified in PowerAuth authentication
                                     process or MAC token based authentication.
 -D,--device-info <arg>              Information about user device.
 -e,--endpoint <arg>                 Deprecated option, use the resource-id option instead.
 -E,--resource-id <arg>              In case the specified method is 'authenticate' or
                                     'authenticate-encrypt', this field specifies a URI identifier,
                                     as specified in PowerAuth authentication process.
 -eb,--enable-biometry               In case the specified method is 'confirm', this field specifies
                                     whether biometric factor should be enabled.
 -g,--algorithm <arg>                SharedSecret algorithm name.
 -h,--help                           Print this help manual.
 -H,--http-header <key=value>        Use provided HTTP header for communication
 -hs,--help-steps                    PowerAuth supported steps and versions.
 -hv,--help-versions                 PowerAuth supported versions and steps.
 -I,--identity-file <arg>            In case the specified method is 'create-custom', this field
                                     specifies the path to the file with identity attributes.
 -i,--invalidSsl                     Client may accept invalid SSL certificate in HTTPS
                                     communication.
 -k,--key-identifier <arg>           Key identifier for vault unlock, use 'KEK_DEVICE_PRIVATE',
                                     'KDK_APP_VAULT_KNOWLEDGE', or 'KDK_APP_VAULT_2FA'.
 -l,--auth-code-type <arg>           In case the specified method is 'authenticate' or
                                     'authenticate-encrypt', this field specifies an authentication
                                     code type, as specified in PowerAuth authentication process.
 -m,--method <arg>                   What API method to call, available names are 'create',
                                     'status', 'remove', 'authenticate', 'unlock', 'create-custom',
                                     'create-token', 'validate-token', 'remove-token', 'encrypt',
                                     'authenticate-encrypt', 'token-encrypt', 'start-upgrade', and
                                     'confirm-upgrade'.
 -n,--password-new <arg>             New password used for a knowledge-related key encryption. If
                                     not specified, an interactive input is required.
 -o,--scope <arg>                    ECIES encryption scope: 'application' or 'activation'.
 -p,--password <arg>                 Password used for a knowledge-related key encryption. If not
                                     specified, an interactive input is required.
 -P,--platform <arg>                 User device platform.
 -q,--qr-code-data <arg>             Data for offline authentication encoded in QR code.
 -r,--reason <arg>                   Reason why vault is being unlocked.
 -s,--status-file <arg>              Path to the file with the activation status, serving as the
                                     data persistence.
 -S,--token-secret <arg>             Token secret (Base64 encoded bytes), in case of
                                     'token-validate' method.
 -t,--http-method <arg>              In case the specified method is 'authenticate',
                                     'authenticate-encrypt' or 'token-encrypt', this field specifies
                                     a HTTP method, as specified in PowerAuth authentication
                                     process.
 -T,--token-id <arg>                 Token ID (UUID4), in case of 'token-validate' method.
 -u,--url <arg>                      URL used for the request.
 -v,--version <arg>                  PowerAuth protocol version.
 -y,--dry-run                        In case the specified method is 'authenticate',
                                     'authenticate-encrypt', 'validate-token' or 'token-encrypt' and
                                     this attribute is specified, the step is stopped right after
                                     authenticating the request body and preparing appropriate
                                     headers.
```

## Troubleshooting

**Everything should be deployed correctly but utility cannot connect.**

If you are using HTTPS, make sure you are using a valid SSL certificate or that you use the "-i" option.

## License

All PowerAuth command-line tool sources are licensed using Apache 2.0 license, you can use them with no restriction. Note that most of the PowerAuth backend components use the AGPL v3.0 license. If you are using PowerAuth, please let us know. We will be happy to share and promote your project.
