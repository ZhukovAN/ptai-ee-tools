# Consul setup for local PT AI EE integration service deployment
1. Create policy for integrationService "AIE-integrationService-ServiceRegister" as:
```
service_prefix "integrationService" {
    policy = "write" intentions = "write"
}
```
2. Create policy "AIE-integrationService-SettingsRead" for services/integrationService/data access as:
```
key_prefix "services/integrationService/data" {
	policy = "read"
}
```
3. Spring Consul API discovery client uses Consul health API (https://www.consul.io/api/health.html) to get info about services so we need to setup ACL. Create policy "AIE-integrationService-CatalogRead" for reading PT AI EE services from consul as:
```
service_prefix "" {
    policy = "read"
}
node_prefix "" {
    policy = "read"
}
```
4. Create integrationService token "Token for service: integrationService", grant policies "AIE-integrationService-ServiceRegister", "AIE-integrationService-SettingsRead" and "AIE-integrationService-CatalogRead" and set it in bootstrap.yml config parameter or as -Dspring.cloud.consul.token=<token> in the integration service start parameters

# Appendix
## Settings priorities
The consul config is given the highest priority by default. You can set spring.cloud.config.override-none=true and it will make external config the lowest priority. You can set spring.cloud.config.override-system-properties=false which will put them below system properties, which will also make cli args higher priority (from https://github.com/spring-cloud/spring-cloud-consul/issues/254#issuecomment-281159761)


