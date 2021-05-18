# PT Application Inspector CI/CD plugins bundle
Set of CI/CD plugins that allow to implement application security testing (AST) in build pipelines using Positive Technologies Applivation Inspector tool ([link](https://www.ptsecurity.com/ww-en/products/ai/)).
## Build plugins
### Build plugins using Gradle
To build plugins bundle using Gradle you need to execute ```build``` Gradle task:
```
$ ./gradlew build
```
Jenkins and Teamcity plugins will be built for CI versions defined in ```gradle.properties``` file but may be redefined using ```-P``` option:
```
$ ./gradlew build -P jenkinsVersion=2.150.2 -P teamcityVersion=2020.1
```
### Build plugins using Docker
Execute ```docker build``` command in project root:
```
docker build --tag ptai-ee-tools:latest .
```
## Jenkins and Teamcity plugins debugging
Both Jenkins and Teamcity Gradle plugins are support starting CI server in debug mode that allows plugin developer to connect to server using IDE tools and debug plugin code. 
### Jenkins plugin debugging 
To start Jenkins with debug port 8000, execute ```server``` Gradle task with `--debug-jvm` flag:
```
$ ./gradlew server --debug-jvm
```
See additional info on gradle-jpi-plugin [page](https://github.com/jenkinsci/gradle-jpi-plugin).
### Teamcity plugin debugging
To start Teamcity server and agents with debug ports 10111 and 10112 accordingly, execute ```startTeamcity``` Gradle task:
```
$ ./gradlew startTeamcity
```
Teamcity distribution is to be downloaded and installed prior to starting:
```
$ ./gradlew downloadTeamcity
$ ./gradlew installTeamcity
```
See additional info on gradle-teamcity-plugin [page](https://github.com/rodm/gradle-teamcity-plugin).
