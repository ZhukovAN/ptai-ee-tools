# AI.Enterprise.Integration.RestApi.Api.SastControllerApi

All URIs are relative to *https://127.0.0.1:8443*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetJobResultUsingGET**](SastControllerApi.md#getjobresultusingget) | **GET** /api/sast/result | getJobResult
[**GetJobResultsUsingGET**](SastControllerApi.md#getjobresultsusingget) | **GET** /api/sast/results | getJobResults
[**GetJobStateUsingGET**](SastControllerApi.md#getjobstateusingget) | **GET** /api/sast/state | getJobState
[**ScanJsonManagedUsingPOST**](SastControllerApi.md#scanjsonmanagedusingpost) | **POST** /api/sast/scan-json-managed | scanJsonManaged
[**ScanUiManagedUsingPOST**](SastControllerApi.md#scanuimanagedusingpost) | **POST** /api/sast/scan-ui-managed | scanUiManaged
[**UploadUsingPOST**](SastControllerApi.md#uploadusingpost) | **POST** /api/sast/upload | upload



## GetJobResultUsingGET

> System.IO.Stream GetJobResultUsingGET (int buildNumber, string artifact)

getJobResult

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetJobResultUsingGETExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var buildNumber = 56;  // int | buildNumber
            var artifact = artifact_example;  // string | artifact

            try
            {
                // getJobResult
                System.IO.Stream result = apiInstance.GetJobResultUsingGET(buildNumber, artifact);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.GetJobResultUsingGET: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **buildNumber** | **int**| buildNumber | 
 **artifact** | **string**| artifact | 

### Return type

**System.IO.Stream**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/octet-stream

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetJobResultsUsingGET

> List&lt;string&gt; GetJobResultsUsingGET (int buildNumber)

getJobResults

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetJobResultsUsingGETExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var buildNumber = 56;  // int | build-number

            try
            {
                // getJobResults
                List<string> result = apiInstance.GetJobResultsUsingGET(buildNumber);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.GetJobResultsUsingGET: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **buildNumber** | **int**| build-number | 

### Return type

**List<string>**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetJobStateUsingGET

> JobState GetJobStateUsingGET (int buildNumber, int startPos)

getJobState

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetJobStateUsingGETExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var buildNumber = 56;  // int | build-number
            var startPos = 56;  // int | start-pos

            try
            {
                // getJobState
                JobState result = apiInstance.GetJobStateUsingGET(buildNumber, startPos);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.GetJobStateUsingGET: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **buildNumber** | **int**| build-number | 
 **startPos** | **int**| start-pos | 

### Return type

[**JobState**](JobState.md)

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ScanJsonManagedUsingPOST

> int ScanJsonManagedUsingPOST (string projectName, string node, string settings, string policy)

scanJsonManaged

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class ScanJsonManagedUsingPOSTExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var projectName = projectName_example;  // string | project-name
            var node = node_example;  // string | node
            var settings = settings_example;  // string | settings
            var policy = policy_example;  // string | policy

            try
            {
                // scanJsonManaged
                int result = apiInstance.ScanJsonManagedUsingPOST(projectName, node, settings, policy);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.ScanJsonManagedUsingPOST: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projectName** | **string**| project-name | 
 **node** | **string**| node | 
 **settings** | **string**| settings | 
 **policy** | **string**| policy | 

### Return type

**int**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **201** | Created |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ScanUiManagedUsingPOST

> int ScanUiManagedUsingPOST (string projectName, string node)

scanUiManaged

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class ScanUiManagedUsingPOSTExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var projectName = projectName_example;  // string | project-name
            var node = node_example;  // string | node

            try
            {
                // scanUiManaged
                int result = apiInstance.ScanUiManagedUsingPOST(projectName, node);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.ScanUiManagedUsingPOST: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projectName** | **string**| project-name | 
 **node** | **string**| node | 

### Return type

**int**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **201** | Created |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UploadUsingPOST

> ResponseEntity UploadUsingPOST (Object current, System.IO.Stream file, Object project, Object total)

upload

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class UploadUsingPOSTExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new SastControllerApi(Configuration.Default);
            var current = new Object(); // Object | current
            var file = BINARY_DATA_HERE;  // System.IO.Stream | file
            var project = new Object(); // Object | project
            var total = new Object(); // Object | total

            try
            {
                // upload
                ResponseEntity result = apiInstance.UploadUsingPOST(current, file, project, total);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling SastControllerApi.UploadUsingPOST: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **current** | [**Object**](Object.md)| current | 
 **file** | **System.IO.Stream**| file | 
 **project** | [**Object**](Object.md)| project | 
 **total** | [**Object**](Object.md)| total | 

### Return type

[**ResponseEntity**](ResponseEntity.md)

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: multipart/form-data
- **Accept**: */*

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |
| **201** | Created |  -  |
| **401** | Unauthorized |  -  |
| **403** | Forbidden |  -  |
| **404** | Not Found |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

