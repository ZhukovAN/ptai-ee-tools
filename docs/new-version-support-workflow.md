# How to add new PT AI version support

To add new PT AI version we need to:

- import and refactor OpenAPI definitions

## Add new OpenAPI definitions to ptai-rest-api module
- Download definitions from https://${your.ptai.server}/swagger/vXXX/swagger.yaml and save it as `ptai-rest-api/src/main/resources/api/vXXX/original/yml/swagger.yaml` file
- As original definition defines global "Bearer" authentication scheme but we need to use API key for initial authentication, move all the /api/auth endpoints and type definitions into `ptai-rest-api/src/main/resources/api/vXXX/auth.yaml` file. Add API key security scheme to `auth.yaml`
- Save original `swagger.yaml` with /api/auth definitions removed as `ptai-rest-api/src/main/resources/api/vXXX/swagger.yaml` file
- Use online OpenAPI editor to quickly find and fix semantic errors in `swagger.yaml` like `Declared path parameter "language" needs to be defined as a path parameter at either the path or operation level`
- Fix `/api/store/{projectId}/sources` POST request definition by adding `requestBody` section
- Add `ApiKeyAuth` in `securitySchemes` component in auth.yaml, then fix `/api/auth/refreshToken` & `/api/auth/signin` requests in auth.yaml by adding `security: - ApiKeyAuth: [] `  
- Download notifications definitions from https://${your.ptai.server}/swagger/notifications/notifications.yaml and save it as `ptai-rest-api/src/main/resources/api/vXXX/notifications.yml`
- Add build tasks to `ptai-rest-api/build.gradle` file
- Build api client by gradle task
- Support tests by path `ptai-rest-api/src/test/java/com/ptsecurity/appsec/ai/ee/server/vXXX`

## Add new generic-client-lib

- Support new code which use rest-api module ver XXX by path: `generic-client-lib/src/main/java/com/ptsecurity/appsec/ai/ee/utils/ci/integration/api/vXXX`
- Support tests by path `generic-client-lib/src/test/java/com/ptsecurity/appsec/ai/ee/utils/ci/integration/api/vXXX`

## Support ptai-data-structures

- Add new enum value in `ptai-data-structures/src/main/java/com/ptsecurity/appsec/ai/ee/scan/result/ScanBrief.java`
- Append new ver in method display name `generateScanResults` in `ptai-data-structures/src/test/java/com/ptsecurity/appsec/ai/ee/scan/brief/ScanBriefDetailedTest.java`

## Generate test resources

- Advice: run each generate recourse task with debug and breakpoint at end, otherwise generated resources will be cleared after the process completes. The path to the generated resources can be seen in debug

### Server connection setup

 - Create configuration.yml file in path `ptai-rest-api/src/testFixtures/resources` by template `configuration.template.yml`
 - Ca cert you can download from server using browser

### Generate ptai-data-structures test resources
 
 - Generate `ptai-data-structures/src/testFixtures/resources/json/scan/brief/detailed/vXXX` by `generateScanResults` method in `ptai-data-structures/src/test/java/com/ptsecurity/appsec/ai/ee/scan/brief/ScanBriefDetailedTest.java`
 - Generate `ptai-data-structures/src/testFixtures/resources/json/scan/result/vXXX` by `generateScanResults` method in `generic-client-lib/src/test/java/com/ptsecurity/appsec/ai/ee/utils/ci/integration/api/vXXX/ConverterTest.java`  
 - README for more information `ptai-data-structures/src/test/README.md`

### Generate ptai-rest-api test resources

- Generate `ptai-rest-api/src/testFixtures/resources/vXXX/json` by `generateRestApiDataStructures` method in `generic-client-lib/src/test/java/com/ptsecurity/appsec/ai/ee/utils/ci/integration/api/vXXX/RestApiDataStructuresIT.java`
- README for more information `ptai-rest-api/src/test/README.md`

## Update info

- Update API version in `gradle.properties`
- Update `CHANGELOG.md`