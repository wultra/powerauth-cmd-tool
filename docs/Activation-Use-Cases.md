# Activation Use Cases

The life cycle of Activations (Registrations in PowerAuth Cloud terminology) managed using the Command-Line Tool.

## Create Activation

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

## Get Activation Status

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

## Remove the Activation

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

## Confirm the Activation

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

## Change Password for the Knowledge Factor

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

## Set Up Biometric Factor

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

## Remove Biometric Factor

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

## Custom Attributes for Activation

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

## Start Upgrade

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

## Confirm Upgrade

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