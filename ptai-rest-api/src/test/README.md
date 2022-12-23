# PT AI plugin test resources
### ptai-rest-api
Test resources here are scan settings, results and issues:
+ src\testFixtures\resources\{version}\json\issuesModel\junit-{project}.{locale}.json.7z
+ src\testFixtures\resources\{version}\json\scanResult\junit-{project}.json
+ src\testFixtures\resources\{version}\json\scanSettings\junit-{project}.json

These files are generated using special "development" unit test RestApiDataStructuresIT.generateRestApiDataStructures. Test uses configuration.yml file to connect to PT AI server, scans code and saves PT AI REST API responses to temp folder where those may be copied from.