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
## Supported Use-Cases

- [Activation Use Cases](./Activation-Use-Cases.md)
- [Authentication Use Cases](./Authentication-Use-Cases.md)
- [Token Use Cases](./Token-Use-Cases.md)
- [Operation Use Cases](./Operation-Use-Cases.md)
- [Encryption Use Cases](./Encryption-Use-Cases.md)

## Troubleshooting

**Everything should be deployed correctly but utility cannot connect.**

If you are using HTTPS, make sure you are using a valid SSL certificate or that you use the "-i" option.

## License

All PowerAuth command-line tool sources are licensed using Apache 2.0 license, you can use them with no restriction. Note that most of the PowerAuth backend components use the AGPL v3.0 license. If you are using PowerAuth, please let us know. We will be happy to share and promote your project.
