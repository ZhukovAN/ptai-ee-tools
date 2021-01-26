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
