# Operation Use Cases

Operation cycle can be simulated using the Command-Line Tool. The operations are utilizing Authentication Codes and [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication).

## Get Pending Operation

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

## Claim Non-Personalized Operation

A non-personalized operation can be claimed on the server using [Token Based Authentication](https://github.com/wultra/powerauth-restful-integration/blob/develop/docs/RESTful-API-for-Spring.md#use-token-based-authentication). This uses the `validate-token` method; see [Validate Token](./Token-Use-Cases.md#validate-token) above for details.

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

## Get Operation Detail

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

## Approve Operation

An operation can be approved on the server using the `authenticate` method (see [Validate the Authentication Code](./Token-Use-Cases.md#validate-the-authentication-code)). The `data` field from the Get Operation Detail / Claim response must be included in the request.

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
    "data": "Operation data that has been signed; must match the operation data returned by the detail or claim API"
  }
}
```

The parameter `auth-code-type` must correspond to expected factors required to approve the operation.
