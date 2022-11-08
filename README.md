# PT Application Inspector CI/CD plugins bundle
Set of CI/CD plugins that allow to implement application security testing (AST) in build pipelines using Positive Technologies Application Inspector tool ([link](https://www.ptsecurity.com/ww-en/products/ai/)).
## Build plugins
Starting with plugins version 3.6.2 Gradle build script use com.palantir.git-version plugin to inject SCM commit hash into manifests. That means you need use ```git clone``` command to download sources.  
### Build plugins using Gradle
To build plugins bundle using Gradle you need to execute ```build``` Gradle task:
```
$ ./gradlew build
```
Jenkins and Teamcity plugins will be built for CI versions defined in ```gradle.properties``` file but may be redefined using ```-P``` option:
```
$ ./gradlew build -P jenkinsVersion=2.150.2 -P teamcityVersion=2020.1
```
### Build plugins using Docker Gradle image
Execute ```docker run``` command in project root:
```
docker run --rm -u root -v "$PWD":/home/gradle/project -w /home/gradle/project gradle:7.1.1-jdk8 gradle build --no-daemon
```
### Build executable Docker container with CLI plugin
Execute ```docker build``` command in project root:
```
docker build --tag ptai-ee-tools:latest .
```
Start container using ```docker run``` command:
```
docker run --rm -it ptai-ee-tools:latest
```
## Jenkins and Teamcity plugins debugging
Both Jenkins and Teamcity Gradle plugins are support starting CI server in debug mode that allows plugin developer to connect to server using IDE tools and debug plugin code. 
### Jenkins plugin debugging
#### Server-side debugging
To start Jenkins with debug port 8000, execute ```server``` Gradle task with `--debug-jvm` flag:
```
$ ./gradlew server --debug-jvm
```
See additional info on gradle-jpi-plugin [page](https://github.com/jenkinsci/gradle-jpi-plugin).
#### Jenkins build agent debugging
As part of plugin functions may be executed on build agents, sometimes we need to run build agent in debug mode. To do so start Jenkins agent JAR using following command:
```
java -jar -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8765 agent.jar -jnlpUrl http://localhost:8080/computer/ast%2Dagent/jenkins-agent.jnlp -workDir "C:\DATA\DEVEL\TEST"
```
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
## Launch integration tests
All integration tests are marked as "slow", "integration", "development" and "jenkins". These tests interact with PT AI instance that is to be available via HTTPS REST API. PT AI server connection settings aren't stored in repository but are to be defined in ptai-test-tools/src/testFixtures/resources/configuration.yml file as follows:
```yaml
connections:
  ptai40: &current
    version: V40
    url: https://ptai4.domain.org:443/
    token: TOKEN_GOES_HERE
    user: root
    password: GUESS_WHAT_GOES_HERE
    ca: keys/domain.org.pem
    insecure: false
  ptai36:
    version: V36
    url: https://ptai.domain.org:443/
    token: TOKEN_GOES_HERE
    user: Administrator
    password: GUESS_WHAT_GOES_HERE
    ca: keys/domain.org.pem
    insecure: false
current: *current
```
### Slow tests
Long-running tests include these containing JWT token refresh check etc. These tests last very long time and to be launched separately:
```
$ ./gradlew clean build slowTest
```
### Generic integration tests
Generic integration tests use predefined vulnerable source packs from generic-client-lib/src/testFixtures/resources/code folder. Use following command to run these tests:
```
$ ./gradlew clean build integrationTest
```
### Development integration tests
Development integration tests aren't supposed to be started during build. Their main purpose is to launch scans and store PT AI server responses to use them as JUnit tests resources. There's no dedicated Gradle task to run these tests, those are to be executed from IDE.
### Jenkins integration tests
Jenkins' integration tests use embedded Jenkins server to create AST jos and launch them. Use following command to run these tests:
```
$ ./gradlew clean build jenkinsTest
```
## Use advanced settings
Some parts of plugin internal behaviour aren't accessible from UI or via CLI parameters. Those advanced settings are to be defined as key / value pairs (see AdvancedSettings.java for possible values). For example, plugins remove JWT and API tokens data from trace logs but you may override that using `logging.http.credentials` advanced setting:
```
java -Dptai.logging.http.credentials=true -jar ptai-cli-plugin.jar check-server --url https://ptai.domain.org --token TOKEN_GOES_HERE
```