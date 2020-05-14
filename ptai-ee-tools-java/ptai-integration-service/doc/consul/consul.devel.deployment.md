# How to setup consul on a development host and join it to PT AI EE server Consul node
In order to test locally deployed integration service it is required to deploy local consul server that is to be part of PT AI consul cluster.
## Make PT AI EE Consul instance to listen on external interfaces
1. Check if PT AI EE node consul instance listens on a IP address different from 127.0.0.1 and replace 127.0.0.1 with actual IP address (fields bind_addr and advertise_addr in serverConfig.json):
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
        "bind_addr": "192.168.0.51",
        "advertise_addr": "192.168.0.51",
        "ports": {
            "http": 8500
        },
        "acl": {
            "enabled": true,
            "default_policy": "deny",
            "down_policy": "extend-cache",
            "tokens": {
                "master": "d5f0a836-cfaa-4a4c-bffb-d2b8ec8443a2"
            }
        }
    }
    ```
2. Restart Consul service on PT AI EE host
## Create policy and token to allow remote connect to PT AI EE Consul instance
1. Create devel-node agent policy "devel-AIE-AgentPolicy" as:
    ```
    node "devel-node" {
        policy = "write"
    }
    ```
2. Create agent token "Token for node: devel-node" and grant "devel-AIE-AgentPolicy" to that token
## Deploy Consul on the development host 
1. Download and unzip Consul
2. Create serverConfig.json and setup advertise_addr as development host external IP and default token to "Token for node: devel-node":
    ```
    {
        "log_level": "trace",
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
        "advertise_addr": "192.168.0.50",
        "ports": {
            "http": 8500
        },
        "acl": {
            "enabled": true,
            "default_policy": "deny",
            "down_policy": "extend-cache",
            "tokens": {
                "default": "a2edd43b-c0ed-d161-9bc1-6038b1b49307"
            }
        }
    }
    ```
3. Start development node Consul instance:
    ```
    consul.exe agent -config-file=serverConfig.json -join=192.168.0.51
    ```

# Appendix

## Possible errors
### Certificate signed by an unknown authority
Copy custom CA certificates to /etc/ssl/certs folder of a Consul container
