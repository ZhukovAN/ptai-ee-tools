# AI.Enterprise.Integration.RestApi.Api.OauthControllerApi

All URIs are relative to *https://127.0.0.1:8443*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetJwtTokenUsingPOST**](OauthControllerApi.md#getjwttokenusingpost) | **POST** /oauth/token | Login user by client id / secret (those are passed as a basic auth fields) and login / password or refresh-token



## GetJwtTokenUsingPOST

> JwtResponse GetJwtTokenUsingPOST (string username = null, string password = null, string refreshToken = null, string grantType = null)

Login user by client id / secret (those are passed as a basic auth fields) and login / password or refresh-token

### Example

```csharp
using System.Collections.Generic;
using System.Diagnostics;
using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Client;
using AI.Enterprise.Integration.RestApi.Model;

namespace Example
{
    public class GetJwtTokenUsingPOSTExample
    {
        public static void Main()
        {
            Configuration.Default.BasePath = "https://127.0.0.1:8443";
            // Configure HTTP basic authorization: Basic
            Configuration.Default.Username = "YOUR_USERNAME";
            Configuration.Default.Password = "YOUR_PASSWORD";

            var apiInstance = new OauthControllerApi(Configuration.Default);
            var username = username_example;  // string |  (optional) 
            var password = password_example;  // string |  (optional) 
            var refreshToken = refreshToken_example;  // string |  (optional) 
            var grantType = grantType_example;  // string |  (optional) 

            try
            {
                // Login user by client id / secret (those are passed as a basic auth fields) and login / password or refresh-token
                JwtResponse result = apiInstance.GetJwtTokenUsingPOST(username, password, refreshToken, grantType);
                Debug.WriteLine(result);
            }
            catch (ApiException e)
            {
                Debug.Print("Exception when calling OauthControllerApi.GetJwtTokenUsingPOST: " + e.Message );
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
 **username** | **string**|  | [optional] 
 **password** | **string**|  | [optional] 
 **refreshToken** | **string**|  | [optional] 
 **grantType** | **string**|  | [optional] 

### Return type

[**JwtResponse**](JwtResponse.md)

### Authorization

[Basic](../README.md#Basic)

### HTTP request headers

- **Content-Type**: application/x-www-form-urlencoded
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

