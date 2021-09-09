
## Prepare config file
1. Open PowerAuth admin
2. Create new application
3. Create a `config.json` file according the created application
```
{
  "applicationId": 1,
  "applicationName": "Application Name",
  "applicationKey": "application key in Base64",
  "applicationSecret": "application secret in Base64",
  "masterPublicKey": "master public key in Base64"
}
```

## Clear data in test database
```sql
TRUNCATE pa_activation_history CASCADE;
TRUNCATE pa_signature_audit CASCADE;
TRUNCATE pa_activation CASCADE;
```

## Run test
```shell
cd powerauth-load-test
mvn gatling:test -Dgatling.simulationClass=com.wultra.powerauth.test.PowerAuthLoadTest \
-DconfigFile="directory_with_the_config_file/config.json" \
-DpowerAuthServerUrl=http://localhost:8080 \
-DpowerAuthRestServerUrl=http://localhost:8081 \
-DnumberOfDevices=1
```
