# Token Use Cases

The use cases related to creation and usage of [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication).

## Create Token

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

## Validate Token

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

## Remove Token

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
