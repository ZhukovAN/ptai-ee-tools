package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import lombok.NonNull;
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
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.joor.Reflect.on;

/**
 * As different openapi-generated XxxApi and ApiClient classes aren't implement
 * common interfaces and aren't inherited from some base class, we need easy way
 * to call methods with same signatures like setWriteTimeout etc. We'll use
 * reflection to do that
 */
public class ApiClientHelper {

    private final Object apiClient;

    public ApiClientHelper(@NonNull Object api) {
        apiClient = on(api).call("getApiClient").get();
    }

    protected static class InsecureX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    @SneakyThrows
    public static X509TrustManager createTrustManager(final String caCertsPem, boolean insecure) {
        if (insecure) return new InsecureX509TrustManager();
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

    /**
     * Initialize XxxApi's ApiClient: set up URL, timeouts, trusted
     * certificate chains and jwt authentication class
     * @param client from where to get URL, timeouts etc. and whom APIs to init with these values
     */
    @SneakyThrows
    public static void initApiClient(@NonNull final AbstractApiClient client) {
        @NonNull ConnectionSettings connectionSettings = client.getConnectionSettings();

        for (Object api : client.getApis()) {
            // Set API client URL and timeout
            ApiClientHelper helper = new ApiClientHelper(api)
                    .setBasePath(connectionSettings.getUrl())
                    .setReadTimeout(connectionSettings.getTimeout())
                    .setWriteTimeout(connectionSettings.getTimeout());
            // If custom certificates are defined, set API clients with those
            if (null != client.getConnectionSettings().getCaCertsPem())
                helper.setSslCaCert(CertificateHelper.cleanupCaPem(connectionSettings.getCaCertsPem()));

            X509TrustManager trustManager = createTrustManager(connectionSettings.getCaCertsPem(), connectionSettings.isInsecure());

            OkHttpClient.Builder builder = helper.getHttpClient().newBuilder()
                    .hostnameVerifier((hostname, session) -> true)
                    .authenticator(new JwtAuthenticator(client))
                    .addInterceptor(new LoggingInterceptor())
                    .protocols(Collections.singletonList(Protocol.HTTP_1_1));
            if (null != trustManager) {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
            }
            helper.setHttpClient(builder.build());
        }
    }

    protected ApiClientHelper setBasePath(String path) {
        on(apiClient).call("setBasePath", path);
        return this;
    }

    protected ApiClientHelper setReadTimeout(int value) {
        on(apiClient).call("setReadTimeout", value);
        return this;
    }

    protected ApiClientHelper setWriteTimeout(int value) {
        on(apiClient).call("setWriteTimeout", value);
        return this;
    }

    @SuppressWarnings("UnusedReturnValue")
    protected ApiClientHelper setSslCaCert(InputStream data) {
        on(apiClient).call("setSslCaCert", data);
        return this;
    }

    private void setHttpClient(OkHttpClient client) {
        on(apiClient).call("setHttpClient", client);
    }

    private OkHttpClient getHttpClient() {
        return on(apiClient).call("getHttpClient").get();
    }

    @SuppressWarnings("UnusedReturnValue")
    public ApiClientHelper setApiKey(String key) {
        on(apiClient).call("setApiKey", key);
        return this;
    }

    public ApiClientHelper setApiKeyPrefix(String prefix) {
        on(apiClient).call("setApiKeyPrefix", prefix);
        return this;
    }
}
