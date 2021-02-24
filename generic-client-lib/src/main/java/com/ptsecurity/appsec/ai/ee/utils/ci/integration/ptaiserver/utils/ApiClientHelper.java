package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtAuthenticator;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.joor.Reflect.on;

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
     * certificate chains and jwt authentication class
     * @param client from where to get URL, timeouts etc.
     * @param api API that is to be initialized with parameters above
     */
    @SneakyThrows
    private static void initClientApi(BaseClient client, Object api) {
        ApiClientHelper helper = new ApiClientHelper(api)
                .init()
                .setBasePath(client.getUrl())
                .setReadTimeout(client.getTimeout())
                .setWriteTimeout(client.getTimeout());
        if (null != client.getCaCertsPem())
                helper.setSslCaCert(CertificateHelper.cleanupCaPem(client.getCaCertsPem()));

        X509TrustManager trustManager = createTrustManager(client.getCaCertsPem(), client.isInsecure());

        OkHttpClient.Builder builder = helper.getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .authenticator(new JwtAuthenticator(client, helper))
                .addInterceptor(new LoggingInterceptor())
                .protocols(Arrays.asList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        helper.setHttpClient(builder.build());
    }

    @SneakyThrows
    public static X509TrustManager createTrustManager(final String caCertsPem, boolean insecure) {
        if (insecure) {
            return new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                                               String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                                               String authType) throws CertificateException {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        } else {
            // Create in-memory keystore and fill it with caCertsPem data
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            if (StringUtils.isNotEmpty(caCertsPem)) {
                List<X509Certificate> certs = CertificateHelper.readPem(caCertsPem);
                for (X509Certificate cert : certs)
                    keyStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
            }
            // To avoid trustAnchors parameter must be non-empty we need to process separately
            // empty keystore case
            if (0 == keyStore.size()) return null;
            // Init trustManagerFactory with custom CA certificates
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
        }
    }

    public static void initClientApis(@NonNull final BaseClient client, @NonNull final List<Object> apis) {
        for (Object api : apis) initClientApi(client, api);
    }

    public ApiClientHelper init() {
        apiClient = on(api).call("getApiClient").get();
        return this;
    }

    public ApiClientHelper setBasePath(String path) {
        on(apiClient).call("setBasePath", path);
        return this;
    }

    private ApiClientHelper setReadTimeout(int value) {
        on(apiClient).call("setReadTimeout", value);
        return this;
    }

    private ApiClientHelper setWriteTimeout(int value) {
        on(apiClient).call("setWriteTimeout", value);
        return this;
    }

    private ApiClientHelper setSslCaCert(InputStream data) {
        on(apiClient).call("setSslCaCert", data);
        return this;
    }

    private void setHttpClient(OkHttpClient client) {
        on(apiClient).call("setHttpClient", client);
    }

    private OkHttpClient getHttpClient() {
        return on(apiClient).call("getHttpClient").get();
    }

    public ApiClientHelper setApiKey(String key) {
        on(apiClient).call("setApiKey", key);
        return this;
    }

    public ApiClientHelper setApiKeyPrefix(String prefix) {
        on(apiClient).call("setApiKeyPrefix", prefix);
        return this;
    }
}
