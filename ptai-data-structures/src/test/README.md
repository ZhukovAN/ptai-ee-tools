# PT AI plugin test resources
### ptai-data-structures
+ testFixtures\resources\json\scan\result\{version}\junit-{project}.json.7z
+ testFixtures\resources\json\scan\brief\detailed\{version}\junit-{project}.json.7z
+ packed test applications in testFixtures\resources\code\{project}.{zip|7z}

"Result" files are generated using ConverterTest.generateScanResults unit test. This test uses ptai-rest-api test resources to convert them. "Brief/detailed" files are generated using ScanBriefDetailedTest.generateScanResults unit test from "result" files. Both these tests save results to temp folder where those may be copied from.
