# AI.Enterprise.Integration.RestApi.Api.AdminControllerApi

All URIs are relative to *https://127.0.0.1:8443*

Method | HTTP request | Description
------------- | ------------- | -------------
[**RandomUsingGET**](AdminControllerApi.md#randomusingget) | **GET** /api/admin/random | random



## RandomUsingGET

> string RandomUsingGET ()

random

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class RandomUsingGETExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure API key authorization: Bearer
            Configuration.Default.AddApiKey("Authorization", "YOUR_API_KEY");
            // Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
            // Configuration.Default.AddApiKeyPrefix("Authorization", "Bearer");

            var apiInstance = new AdminControllerApi(Configuration.Default);

            try
            {
                // random
                string result = apiInstance.RandomUsingGET();
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling AdminControllerApi.RandomUsingGET: " + e.Message );
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

**string**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

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

