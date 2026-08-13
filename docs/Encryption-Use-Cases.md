# Encryption Use Cases

The data can be protected by end to end encryption. This feature can be used together with validation of Authentication Codes and usage of MAC Tokens.

## Send Encrypted Data to Server

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

## Send Authenticated and Encrypted Data to Server

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

The data in `request.json` file is authenticated and encrypted using AEAD encryption. See chapter [Validate the Authentication Code](./Authentication-Use-Cases.md#validate-the-authentication-code) which describes authentication parameters.
The encrypted data is sent to a specified endpoint URL.  The base URL is used for PowerAuth Standard RESTful API requests, e.g., to request temporary encryption keys. The endpoint which receives encrypted data needs to decrypt the data, verify data authentication and return encrypted response back to the client. The cmd line tool receives the encrypted response from the server, decrypts it and prints it into the command line.

## Send Encrypted Data with Token Validation to Server

Use this method to send encrypted data with token validation to the server. See chapter [Validate Token](./Token-Use-Cases.md#validate-token) for token parameters.

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
