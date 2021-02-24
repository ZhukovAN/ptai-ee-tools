# PT AI EE Java CLI plugin user manual
This document describes how to download, build and execute PT AI EE Java CLI plugin 
## Get sources
Use Git to fetch sources from repository:
```
git clone https://github.com/PositiveTechnologies/ptaiPlugins.git
```
## Build
You may use two options to build PT AI EE Java CLI plugin: with Docker or using locally installed JDK 8 and Maven version 3.6.3 and above, see steps required below.  

### Using Docker
```
cd ptaiPlugins/ptai-ee-tools-java/
docker run -it --rm --name ptai-ee-tools-java -v "$(pwd)":/usr/src/mymaven -w /usr/src/mymaven maven:3.6.3-jdk-8 mvn clean install -DskipTests=true
cd ptai-cli-plugin/target
```
### Using JDK 8 and Maven 3.6.3
```
cd ptaiPlugins/ptai-ee-tools-java/
mvn clean install -DskipTests=true
cd ptai-cli-plugin/target

```
After build is finished, executable JAR file ptai-cli-plugin-0.1-jar-with-dependencies.jar placed into ptai-cli-plugin/target folder
## Getting usage help
PT AI EE Java CLI plugin supports several different options with help available. Just call executable JAR without parameters:
```
root@host:~/ptaiPlugins/ptai-ee-tools-java/ptai-cli-plugin/target# java -jar ./ptai-cli-plugin-0.1-jar-with-dependencies.jar
Missing required subcommand
Usage: java -jar ptai-cli-plugin.jar [-hV] COMMAND
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  ui-ast                 Calls PT AI for AST. Project settings are defined in
                           the PT AI viewer UI
  json-ast               Calls PT AI for AST. Project settings and policy are
                           defined with JSON files
  check-server           Checks PT AI server connection
  list-report-templates  Lists available PT AI report templates
  generate-report        Generates PT AI report based on AST results
```
Each subcommand also supports usage help output:
```
root@host:~/ptaiPlugins/ptai-ee-tools-java/ptai-cli-plugin/target# java -jar ./ptai-cli-plugin-0.1-jar-with-dependencies.jar ui-ast
Missing required options [--url=<url>, --token=<token>, --input=<path>, --project=<name>]
Usage: java -jar ptai-cli-plugin.jar ui-ast [--report-json=<file>
       [--report-template=<template> -f=<format> -l=<locale>]] [-v] --url=<url>
       -t=<token> --input=<path> [--output=<path>] -p=<name> [-i=<pattern>]
       [-e=<pattern>] [--truststore=<path>] [--async]
Calls PT AI for AST. Project settings are defined in the PT AI viewer UI
      --url=<url>            PT AI integration service URL, i.e. https://ptai.
                               domain.org:8443
      --report-json=<file>   JSON file that defines reports to be generated
      --report-template=<template>
                             Template name of report to be generated
  -t, --token=<token>        PT AI integration service API token
  -f, --report-format=<format>
                             Format type of report to be generated, one of:
                               HTML, XML, JSON, PDF
      --input=<path>         Source file or folder to scan
  -l, --report-locale=<locale>
                             Locale ID of report to be generated, one of EN, RU
      --output=<path>        Folder where AST reports are to be stored. By
                               default .ptai folder is used
  -p, --project=<name>       Project name how it is setup and seen in the PT AI
                               viewer
  -i, --includes=<pattern>   Comma-separated list of files to include to scan.
                               The string is a comma separated list of includes
                               for an Ant fileset eg. '**/*.jar'(see http://ant.
                               apache.org/manual/dirtasks.html#patterns). The
                               base directory for this fileset is the sources
                               folder
  -e, --excludes=<pattern>   Comma-separated list of files to exclude from
                               scan. The syntax is the same as for includes
      --truststore=<path>    Path to PEM file that stores trusted CA
                               certificates
      --async                Do not wait AST to complete and exit immediately
  -v, --verbose              Provide verbose console log output
Exit Codes:
  0      AST complete, policy (if set up) assessment success
  1      AST complete, policy (if set up) assessment failed
  2      AST complete, policy (if set up) assessment success, minor warnings
           were reported
  3      AST failed
  1000   Invalid input
```
## Check PT AI EE server connection
Use check-server subcommand to verify if PT AI EE server accessible:
```
root@host:~/ptaiPlugins/ptai-ee-tools-java/ptai-cli-plugin/target# java -jar ./ptai-cli-plugin-0.1-jar-with-dependencies.jar check-server --token 6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5 --url https://ptai.domain.org --truststore ../src/test/resources/keys/domain.org.pem
Healthy services: 13 out of 13, License: 554433, vaildity period: from 2019-05-10T00:00Z to 2021-01-04T06:20:01Z
```
You may see **truststore** parameter that defines PEM-encoded file with trusted certificates. You may omit this parameter if PT AI EE server's certificate issued by certificate authority which CA certificates are placed to JDK's cacerts file
## Scan sources using UI-defined settings
Use ui-ast subcommand to scan sources with settings defined usilg PT AI Viewer:
```
java -jar ptai-cli-plugin-0.1-jar-with-dependencies.jar ui-ast --token 6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5 --url https://ptai.domain.org --truststore ../src/test/resources/keys/domain.org.pem --project app01 --input ./app01
PT AI project ID is 23f6879c-f83c-4919-8a6c-150c543ac373
...
Scan started
Initialize -> RestoreScanData 0%
...
Precheck -> JspDecompiling 0%
Precheck -> JspDecompiling 100%
Scan 0%
Scan 1%
...
Scan 100%
Finalize 0%
Finalize 20%
Finalize 100%
Finalize -> StoringResults 0%
...
Finalize -> StoringResults 100%
Done 0%
Scan complete, AST policy assessment success, but there were scan warnings or errors
``` 