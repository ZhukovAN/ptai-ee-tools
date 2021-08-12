## v.3.6.1
### 20201209
+ [Feature] CLI, Jenkins and Teamcity plugins are refactored and use same AstJob approach
+ [Feature] Jenkins and CLI plugins reporting settings changed to allow generation of raw issues JSON and filtered PDF/HTML reports, XML/JSON data exports
+ [Feature] All the HTTP requests and responses are logged using FINEST level
+ [Feature] CLI, Jenkins and Teamcity plugins are now support insecure SSL connections i.e. without CA certificate chain verification
+ [Feature] Valid AST result statuses are SUCCESS, FAILED and INTERRUPTED. If AST is done then initial result is SUCCESS. If policy defined and fail-if-failed is on, status changes to FAILED, if no policy or assessment succeeds and there were scan errors or warnings and fail-if-unstable is on, then status also changes to FAILED    
+ [Fix] Due to some limitations of HTTP/2 API (sometimes it answers HTTP 401 for valid authentication token) all REST API clients now use HTTP/1 protocol
### 20201217
+ [Fix] Restored functions of Teamcity plugin, plan to implement async scan and report generation
+ [Feature] CLI plugin now uses Log4J2 and stores non-trace and trace logs separately
### 20201222
+ [Fix] More existing sources are using ptai-i18n library
+ [Feature] Scan results link saved in ptai.url. But PT AI Viewer not supports it
+ [Feature] Default report locale and format are added
+ [Feature] Teamcity plugin now supports report definitions (UI only, no generation yet)
### 20201230
+ [Feature] Teamcity plugin now supports report generation
### 20210112
+ [Feature] CLI plugin enum parameters are made case-insensitive
+ [Feature] Extended issues filtering syntax implemented, see sample JSON in reports.5.json
+ [Feature] Jenkins plugin reporting locale uses browser locale 
+ [Feature] Jenkins plugin reporting template uses predefined browser locale based names
### 20210122
+ [Fix] "Scan enqueued" event fixed
### 20210125
+ [Feature] Jenkins version changed to 2.263.2
### 20210202
+ [Feature] CLI plugin now supports full and incremental scan modes
+ [Fix] Scan stop API call removed from CLI plugin
### 20210203
+ [Fix] Redundant requestBody content types are deleted from OpenAPI descriptions
+ [Feature] Added request and response body logging for PT AI REST API calls with content type application/json
### 20210224
+ [Fix] "SAST" changed to "AST" in resources
+ [Fix] Ant JAR version changed in generic-client-lib as GitHub's dependabot made that pull request
+ [Feature] GitHub build workflow added
### 20210309
+ [Fix] Hidden "nodeName" parameter removed from Jenkins plugin
+ [Fix] Jenkins credentials plugin version changed to 2.3.14
+ [Fix] Jenkins token-macro plugin version changed to 2.13
+ [Fix] PT AI result URL output removed as it is not supported in PT AI Viewer 
+ [Fix] ScanEnqueued event subscription removed as there's no more handler for it exist. This will fix SignalR exception when event reaches BaseClient
+ [Feature] Full / incremental scan mode option added to Jenkins plugin
+ [Feature] Added zipped sources file size log output
+ [Feature] Full / incremental scan mode option added to Teamcity plugin
### 20210313
+ [Fix] Teamcity plugin build via Dockerfile fixed
### 20210401
+ [ToDo] Investigate Jenkins plugin fail for 2.277.1: build job fails on save
### 20210413
+ [Fix] Dockerfile fixed to allow CLI plugin execution from Gitlab CI
+ [Fix] Ant and Slf4J dependencies are removed from Jenkins's plugin pom.xml file as those JARs versions are managed by parent org.jenkins-ci.plugins artifact that maintains actual BOM of dependencies in accordance with jenkins.version variable, see details [here](https://github.com/jenkinsci/plugin-pom).  
+ [Feature] CLI plugin --use-default-excludes parameter added
### 20210414
+ [Fix] Transitive dependencies to Maven localizer plugin 1.26 are fixed by adding explicit repository URL to parent pom.xml
### 20210529
+ [Feature] "Integration" JUnit tags are added to integration tests
+ [Feature] "Delombok" @param and @return JavaDocs are added
+ [Fixed] Investigate Jenkins plugin fail for 2.277.1: build job fails on save. Separate taglibs are implemented. See [link](https://www.jenkins.io/blog/2020/11/10/major-changes-in-weekly-releases/) for details
+ [Feature] Single Jenkins GlobalConfig class supported
+ [Feature] Gradle now used as a build tool. This allows dynamic dependency versioning to support build for different Jenkins / Teamcity versions
+ [ToDo] Add .ptai folder to default excludes list
+ [ToDo] Implement [SARIF](https://habr.com/ru/company/pvs-studio/blog/541542/) reports generation
+ [Feature] Test fixtures are implemented for generic-client-lib
+ [Fix] ptai-jenkins-plugin build.gradle now also supports X.YYY Jenkins versions
### 20210608
+ [Feature] PT AI trend chart added to Jenkins plugin
+ [Feature] Project- and run-level actions are added to Jenkins plugin to show stats about AST
### 20210616
+ [Feature] REST API naming refactored from <service>.<version> to <version>.<service>
+ [ToDo] Check API calls that return file. Those files are created as temp so it is better to explicitly delete them
+ [ToDo] Reorganize test fixtures: place data parser tests to ptai-rest-api
+ [ToDo] Refactor data structures. Currently plugins like Jenkins one use data types defined in ptai-rest-api and those types are version-dependent. This may cause a problems with plugins update
+ [Fix] ```@NotNull``` changed to Lombok's ```@NonNull```
+ [Fix] Smarter Jenkins plugins version number calculation implemented in build.gradle
+ [Fix] Full / incremental scan mode fixed
### 20210617
+ [Fix] Build timestamp removed from CLI, Jenkins and Teamcity plugins version as it doesn't relate to this. Git commit hash value used instead
+ [Feature] Git hash and branch information added to CLI plugin manifest and shown when it is run with ```--version``` option
+ [Feature] Build metadata added to all jar monifests and to generic-client-lib's build.properties file(s)
+ [Feature] Version number changed to 3.6.2
+ [Feature] Build timestamp format changed to ISO 8601
+ [ToDo] Fix stacked area chart area order
### 20210620
+ [Feature] Scan results data structures refactoring started. Previously plugins like Jenkins used data types defined in ptai-rest-api and those types are version-dependent. This could cause a problems with plugins update as that data stored as an XML representation of Actions
### 20210621
+ [Feature] Project- and build-scope actions are temporarily disabled
### 20210812
+ [Fix] Major code refactoring complete
+ [Feature] Jenkins plugin now supports charts
+ [Fix] Scans stopped from PT AI viewer are terminated in plugins
+ [ToDo] Implement syslog data send. Syslog connection settings are to be taken from PT AI server settings
+ [ToDo] Fix "internal server error" when trying to get scan results for scans deleted / stopped from PT AI viewer
