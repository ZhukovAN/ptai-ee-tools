# Consul setup
In order to test locally deployed integration service it is required to deploy local consul server that is to be part of PT AI consul cluster.
So we need to:
1. Check if PT AI consul instance listens on a IP address different from 127.0.0.1 and replace 127.0.0.1 with actual IP address (fields bind_addr and advertise_addr in serverConfig.json)
2. Create devel-node agent policy "devel-AIE-AgentPolicy" as:
```
node "devel-node" {
    policy = "write"
}
```
3. Create agent token "Token for node: devel-node" and grant "devel-AIE-AgentPolicy" to that token
4. Setup "Token for node: devel-node" in serverConfig.json
5. Create policy for integrationService "devel-AIE-integrationService-ServiceRegister" as:
```
service_prefix "integrationService" {
    policy = "write" intentions = "write"
}
```
6. Create policy "devel-AIE-integrationService-SettingsRead" for services/integrationService/data access as:
```
key_prefix "services/integrationService/data" {
	policy = "read"
}
```
7. Spring Consul API discovery client uses Consul health API (https://www.consul.io/api/health.html) to get info about services so we need to setup ACL. Create policy "devel-AIE-integrationService-CatalogRead" for reading PT AI EE services from consul as:
```
service_prefix "" {
    policy = "read"
}
node_prefix "" {
    policy = "read"
}
```
8. Create integrationService token "Token for service: integrationService", grant policies "devel-AIE-integrationService-ServiceRegister", "devel-AIE-integrationService-SettingsRead" and ""devel-AIE-integrationService-CatalogRead" and set it in bootstrap.yml config parameter

# Appendix

## Possible errors
### Certificate signed by an unknown authority
Copy custom CA certificates to /etc/ssl/certs folder of a Consul container


## Settings priorities
The consul config is given the highest priority by default. You can set spring.cloud.config.override-none=true and it will make external config the lowest priority. You can set spring.cloud.config.override-system-properties=false which will put them below system properties, which will also make cli args higher priority (from https://github.com/spring-cloud/spring-cloud-consul/issues/254#issuecomment-281159761)

## PT AI serverConfig.json
```
{
	"log_level": "err",
	"log_file": "C:\\ProgramData\\Application Inspector\\Logs\\consul\\",
	"server": true,
	"rejoin_after_leave": true,
	"data_dir": "C:\\ProgramData\\Application Inspector\\consul",
	"bootstrap": true,
	"primary_datacenter": "dc1",
	"client_addr": "0.0.0.0",
	"bind_addr": "0.0.0.0",
	"advertise_addr": "10.0.0.3",
	"ports": {
		"http": 8500
	},
	"acl": {
		"enabled": true,
		"default_policy": "deny",
		"down_policy": "extend-cache",
		"tokens": {
			"master": "73e3492f-5d8d-4d4a-a962-935ac5e1bff5"
		}
	}
}
```
## Development node serverConfig.json
```
{
	"log_level": "err",
	"log_file": ".\\logs\\",
	"node_name": "devel-node",
	"server": false,
	"ui": true,
	"rejoin_after_leave": true,
	"data_dir": ".\\client-data\\",
	"bootstrap": false,
	"primary_datacenter": "dc1",
	"client_addr": "0.0.0.0",
	"bind_addr": "0.0.0.0",
	"advertise_addr": "192.168.56.1",
	"ports": {
		"http": 8500
	},
	"acl": {
		"enabled": true,
		"default_policy": "deny",
		"down_policy": "extend-cache",
		"tokens": {
			"default": "2a8dfe77-8423-204b-f0b9-0e3838ac9ef1"
		}
	}
}
```
P.S. That can also be done using CLI. Will need to set master token:
set CONSUL_HTTP_TOKEN=73e3492f-5d8d-4d4a-a962-935ac5e1bff5
consul acl policy list

