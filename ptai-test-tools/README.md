# PT AI plugin tests
## Test resources
Major test resources are located in ptai-rest-api, ptai-data-structures and generic-client-lib projects
### ptai-rest-api
Test resources here are scan settings, results and issues:
+ src\testFixtures\resources\{version}\json\issuesModel\junit-{project}.{locale}.json.7z
+ src\testFixtures\resources\{version}\json\scanResult\junit-{project}.json
+ src\testFixtures\resources\{version}\json\scanSettings\junit-{project}.json

These files are generated using special "development" unit test RestApiDataStructuresIT.generateRestApiDataStructures. Test uses configuration.yml file to connect to PT AI server, scans code and saves PT AI REST API responses to temp folder where those may be copied from.

### ptai-data-structures
+ ptai-data-structures\src\testFixtures\resources\json\scan\result\{version}\junit-{project}.json.7z
+ ptai-data-structures\src\testFixtures\resources\json\scan\brief\detailed\{version}\junit-{project}.json.7z

"Result" files are generated using ConverterTest.generateScanResults unit test. This test uses ptai-rest-api test resources to convert them. "Brief/detailed" files are generated using ScanBriefDetailedTest.generateScanResults unit test from "result" files. Both these tests save results to temp folder where those may be copied from.

### generic-client-lib
Test resources here are: 
+ packed test applications in src\testFixtures\resources\code\{project}.{zip|7z} 
