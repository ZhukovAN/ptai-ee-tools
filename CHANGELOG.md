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
### 20210813
+ [Fix] Scans stopped from CI are terminated in PT AI server
+ [ToDo] Implement enqueued project scan stop from plugin. This requires current scan stage monitoring and if scan isn't started yet, need to delete scan result instead of scan stop
+ [ToDo] Implement UI for terminated / incomplete scans
### 20210817
+ [Fix] Jenkins VirtualChannel throws exception that is inherited from Throwable instead of Exception. But CallHelper processes ava.util.concurrent.Callable lambdas that throw Exception. That means that CallHelper can't process VirtualChannel exceptions and some JDK's like OpenJDK 8 raises build error here. So I had to implement own Callable inside CallHelper that throws Throwable
+ [Feature] Jenkins plugin logo changed. Now it uses icon from PT AI IDE plugins
### 20210819 
+ [Fix] Fixed scan settings change for second and following scans
+ [Feature] UI for terminated / incomplete scans implemented for Jenkins plugin
### 20210820 
+ [Feature] Integration test for project scan settings change using JSON added
+ [Feature] UI for scan stage duration statistic added
+ [Fix] JSON-defined BlackBox engine level processing fixed
+ [Fix] JSON-defined BlackBox engine programming language settings fixed
+ [Feature] Jenkins plugin shows its version on global configuration page (light gray colored text at plugin global settings bottom right corner)
+ [Fix] Ugly headers removed from transfers and reports settings in Jenkins plugin
## v.3.6.4-RC1
### 20210825
+ [Fix] Jenkins plugin version fixed (old Jenkins versions show that data at the very top of screen)
+ [Feature] Multilanguage (EN and RU) scan brief implemented
### 20210826
+ [Feature] Raw scan result now contains localized description
+ [Feature] PT AI server URL added to scan results
+ [Feature] PT AI scan info added to Jenkins build's "summary" section
### 20210901
+ [Feature] CLI plugin supports PT AI project deletion
+ [Feature] CLI plugin supports login / password credentials as these required for critical operations like project delete
+ [Feature] Build script now support publish task
## v.3.6.4
### 20210907
+ [Fix] Jenkins pipeline job PT AI actions fixed
### 20210914
+ [Fix] JWT refresh fixed
+ [Feature] SignalR version update 1.0.0 -> 5.0.9. Need this to check if websocket proxy connection issue can be fixed
+ [Feature] Advanced settings class implemented. Use ```-Dptai.http.response.max.body.size="10"``` Java parameter to restrict HTTP response body size to store to logs 
### 20210916
+ [Fix] Use of LastBuildAction allows plugin to show project-scope actions both for pipeline and freestyle jobs. But this works only if there were at least one successful build (see https://issues.jenkins.io/browse/JENKINS-28479). Added getProjectActions for build step to fix that for at least freestyle projects
+ [Fix] jcenter.bintray.com repository not available. Replaced with https://download.jetbrains.com/teamcity-repository
### 20210927
+ [Fix] "Fail-if-failed" and "fail-if-unstable" settings for Jenkins plugin are changed from boolean to enum. This allows us to mark build step as unstable and thus allow AST results save in pipeline jobs
+ [Fix] Broken symlinks processing fixed. Test task "advancedTest" added as Windows requires "Run as administrator" privilege to create symlinks
+ [Fix] CLI plugin project delete error fixed
### 20211006
+ [Feature] More logging added to report generation
### 20211019
+ [Fix] Bug with custom connection settings in Jenkins pipeline jobs fixed
+ [Fix] Jenkins plugin name changed from "ptaiUiAst" to "ptaiAst". Also all the extension symbol names are made camelcase
### 20211025
+ [Feature] Support for PT AI 3.6.5.1541 added
### 20211102
+ [Fix] Integration tests for incremental scans are removed as those may fail
+ [Feature] Jenkins plugin "fail-if-failed" / "fail-if-unstable" and reports generation are merged to single UI that allows to manually define set of post-AST actions including reports generation, policy processing etc. 
### 20211125
+ [Fix] SignalR version changed to 6.0.0
+ [Feature] SARIF report generation added to Jenkins plugin
### 20211210 
+ [Feature] Jenkins reports now support environment variables macro expansion for file / template names and for JSON filter
+ [Feature] SonarQube's [Generic Issue Import Format](https://docs.sonarqube.org/latest/analysis/generic-issue/) report generation added to Jenkins plugin
### 20211223
+ [Feature] "Include DFD" and "Include glossary" options are added to Jenkins and CLI plugins
### 20211224
+ [Feature] SARIF and SonarQube GIIF reports are added to CLI
+ [Feature] SARIF and SonarQube GIIF reports are added to TeamCity (no filtering yet)
### 20211228
+ [Feature] Raw JSON, SARIF and SonarQube GIIF reports filtering support added to TeamCity plugin
### 20220113
+ [Fix] Macro replacement in Jenkins plugin fixed
### 20220118
+ [Fix] Log4J version changed for CLI plugin due to [vulnerability](https://logging.apache.org/log4j/2.x/security.html)
+ [Feature] Jenkins plugin integration tests implemented
+ [Fix] ClassGraph library replaced with Reflections
+ [Fix] 7z-packed sources are replaced with zip-packed ones as ExtractResourceSCM supports zip archives
### 20220215
+ [Fix] Fixed FileCollector bug where it doesn't add folder entries to zipped file. Processing of such zip files sometimes fails on a PT AI server
### 20220228
+ [Feature] CLI plugin may now use -Dptai.logging.http.response.max.body.size=10 Java option to restrict logged HTTP body size
### 20220310
+ [Feature] Jenkins plugin now supports global- and task-scope defined advanced settings. logging.http.response.max.body.size is supported
### 20220312
+ [Feature] Added logging.http.request.max.body.size, http.request.read.timeout and http.request.write.timeout for Jenkins and CLI plugins
### 20220615
+ [Feature] PT AI 4.0 supported
+ [Feature] As sometimes notifications service connection get lost, polling thread added to generic AST task
+ [ToDo] Remove PDF report generation as PT AI 4.0 REST API no supports it more
+ [ToDo] Remove XML / JSON report generation as PT AI 4.0 REST API no supports it more
+ [Fix] Temporal file cleanup fixed
### 20220624
+ [Fix] Gradle version fixed in Dockerfile
