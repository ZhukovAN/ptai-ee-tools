# How to add new PT AI version support

To add new PT AI version we need to:

- import and refactor OpenAPI definitions

## Add new OpenAPI definitions to ptai-rest-api module
- Download definitions from https://${your.ptai.server}/swagger/vXXX/swagger.yaml and save it as `ptai-rest-api/src/main/resources/api/vXXX/original/yml/swagger.yaml` file
- As original definition defines global "Bearer" authentication scheme but we need to use API key for initial authentication, move all the /api/auth endpoints and type definitions into `ptai-rest-api/src/main/resources/api/vXXX/auth.yaml` file. Add API key security scheme to `auth.yaml`
- Save original `swagger.yaml` with /api/auth definitions removed as `ptai-rest-api/src/main/resources/api/vXXX/swagger.yaml` file
- Use online OpenAPI editor to quickly find and fix semantic errors in `swagger.yaml` like `Declared path parameter "language" needs to be defined as a path parameter at either the path or operation level`
- Fix `/api/store/{projectId}/sources` POST request definition by adding `requestBody` section
- Download notifications definitions from https://${your.ptai.server}/swagger/notifications/notifications.yaml and save it as `ptai-rest-api/src/main/resources/api/vXXX/notifications.yml`
- Add build tasks to `ptai-rest-api/build.gradle` file
## To be continued ...
