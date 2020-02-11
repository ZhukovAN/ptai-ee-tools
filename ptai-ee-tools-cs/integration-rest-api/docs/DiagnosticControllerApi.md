# AI.Enterprise.Integration.RestApi.Api.DiagnosticControllerApi

All URIs are relative to *https://127.0.0.1:8443*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetComponentsStatusUsingGET**](DiagnosticControllerApi.md#getcomponentsstatususingget) | **GET** /api/diagnostic/check | getComponentsStatus
[**GetProject**](DiagnosticControllerApi.md#getproject) | **GET** /api/diagnostic/project | 



## GetComponentsStatusUsingGET

> ComponentsStatus GetComponentsStatusUsingGET ()

getComponentsStatus

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetComponentsStatusUsingGETExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new DiagnosticControllerApi(Configuration.Default);

            try
            {
                // getComponentsStatus
                ComponentsStatus result = apiInstance.GetComponentsStatusUsingGET();
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling DiagnosticControllerApi.GetComponentsStatusUsingGET: " + e.Message );
                Debug.Print("Status Code: "+ e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**ComponentsStatus**](ComponentsStatus.md)

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


## GetProject

> Guid GetProject (string projectName = null)



### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetProjectExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new DiagnosticControllerApi(Configuration.Default);
            var projectName = projectName_example;  // string |  (optional) 

            try
            {
                Guid result = apiInstance.GetProject(projectName);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling DiagnosticControllerApi.GetProject: " + e.Message );
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
 **projectName** | **string**|  | [optional] 

### Return type

**Guid**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OK |  -  |

[[Back to top]](#)
[[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

