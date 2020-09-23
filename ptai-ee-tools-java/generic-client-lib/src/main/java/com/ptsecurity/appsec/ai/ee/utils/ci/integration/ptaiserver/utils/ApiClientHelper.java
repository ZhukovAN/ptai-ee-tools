package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtAuthenticator;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import okhttp3.OkHttpClient;

import java.io.InputStream;
import java.util.List;

import static org.joor.Reflect.*;

/**
 * As different openapi-generated XxxApi and ApiClient classes aren't implement
 * common interfaces and aren't inherited from some base class, we need easy way
 * to call methods with same signatures like setWriteTimeout etc. We'll use
 * reflection to do that
 */
@RequiredArgsConstructor
public class ApiClientHelper {

    @NonNull
    protected Object api;
    private Object apiClient;

    /**
     * Initialize XxxApi and its ApiClient: set up URL, timeouts, trusted
     * certificate chains and JWT authentication class
     * @param client from where to get URL, timeouts etc.
     * @param api API that is to be initialized with parameters above
     */
    protected static void initClientApi(BaseClient client, Object api) {
        ApiClientHelper helper = new ApiClientHelper(api).init();

        helper.setBasePath(client.getUrl());
        helper.setReadTimeout(client.getTimeout());
        helper.setWriteTimeout(client.getTimeout());
        helper.setSslCaCert(CertificateHelper.cleanupCaPem(client.getCaCertsPem()));

        OkHttpClient httpClient = helper.getHttpClient();
        httpClient = httpClient.newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .authenticator(new JwtAuthenticator(client, helper))
                .build();
        helper.setHttpClient(httpClient);
    }

    public static void initClientApis(@NonNull final BaseClient client, @NonNull final Object ... apis) {
        for (Object api : apis) initClientApi(client, api);
    }

    public static void initClientApis(@NonNull final BaseClient client, @NonNull final List<Object> apis) {
        for (Object api : apis) initClientApi(client, api);
    }

    public ApiClientHelper init() {
        apiClient = on(api).call("getApiClient").get();
        return this;
    }

    public void setBasePath(String path) {
        on(apiClient).call("setBasePath", path);
    }

    public void setReadTimeout(int value) {
        on(apiClient).call("setReadTimeout", value);
    }

    public void setWriteTimeout(int value) {
        on(apiClient).call("setWriteTimeout", value);
    }

    public void setSslCaCert(InputStream data) {
        on(apiClient).call("setSslCaCert", data);
    }

    public void setHttpClient(OkHttpClient client) {
        on(apiClient).call("setHttpClient", client);
    }

    public OkHttpClient getHttpClient() {
        return on(apiClient).call("getHttpClient").get();
    }
    public void setApiKey(String key) {
        on(apiClient).call("setApiKey", key);
    }

    public void setApiKeyPrefix(String prefix) {
        on(apiClient).call("setApiKeyPrefix", prefix);
    }
}
