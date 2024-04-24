package com.ptsecurity.appsec.ai.ee.server.v471;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.Environment;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.ApiClient;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v471.auth.model.AuthScope;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.ConnectException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V471;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.misc.tools.helpers.CertificateHelper.createTrustManager;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@Tag("integration")
@Environment(enabledFor = { V471 })
@DisplayName("Test PT AI 4.7.1 authentication calls")
public class AuthTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Successfull connection with custom CA")
    public void authenticateSuccess() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken());
        auth.getApiClient().setBasePath(CONNECTION().getUrl());
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem()));
        X509TrustManager trustManager = createTrustManager(CONNECTION().getCaPem(), CONNECTION().isInsecure());
        OkHttpClient.Builder builder = auth.getApiClient().getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        auth.getApiClient().setHttpClient(builder.build());

        AuthResultModel authResult = assertDoesNotThrow(() -> auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN));
        log.trace("Authentication result: {}", authResult);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid token connection")
    public void authenticateFailInvalidToken() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID());
        auth.getApiClient().setBasePath(CONNECTION().getUrl());
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem()));
        X509TrustManager trustManager = createTrustManager(CONNECTION().getCaPem(), CONNECTION().isInsecure());
        OkHttpClient.Builder builder = auth.getApiClient().getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        auth.getApiClient().setHttpClient(builder.build());

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN);
        } catch (ApiException e) {
            assertEquals(HttpStatus.SC_UNAUTHORIZED, e.getCode());
            log.trace("Exception: ", e);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail non-existent host connection")
    public void authenticateFailNonExistentHost() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID());
        auth.getApiClient().setBasePath("https://" + UUID.randomUUID());
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem()));
        X509TrustManager trustManager = createTrustManager(CONNECTION().getCaPem(), CONNECTION().isInsecure());
        OkHttpClient.Builder builder = auth.getApiClient().getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        auth.getApiClient().setHttpClient(builder.build());

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN);
        } catch (ApiException e) {
            assertTrue(e.getCause() instanceof UnknownHostException);
            log.trace("Exception: ", e);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail inactive host connection")
    public void authenticateFailInactiveHost() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken());
        auth.getApiClient().setBasePath("https://inactive.domain.org");
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(false);

        assertThrows(ApiException.class, () -> auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid service connection")
    public void authenticateFailInvalidHost() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID());
        URL url = new URL(CONNECTION().getUrl());
        auth.getApiClient().setBasePath(url.getProtocol() + "://" + url.getHost() + ":9443");
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem()));
        X509TrustManager trustManager = createTrustManager(CONNECTION().getCaPem(), CONNECTION().isInsecure());
        OkHttpClient.Builder builder = auth.getApiClient().getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        auth.getApiClient().setHttpClient(builder.build());

        assertThrows(ApiException.class, () -> auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid port connection")
    public void authenticateFailInvalidPort() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID());
        URL url = new URL(CONNECTION().getUrl());
        auth.getApiClient().setBasePath(url.getProtocol() + "://" + url.getHost() + ":65535");
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem()));
        X509TrustManager trustManager = createTrustManager(CONNECTION().getCaPem(), CONNECTION().isInsecure());
        OkHttpClient.Builder builder = auth.getApiClient().getHttpClient().newBuilder()
                .hostnameVerifier((hostname, session) -> true)
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        auth.getApiClient().setHttpClient(builder.build());

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN);
        } catch (ApiException e) {
            assertTrue(e.getCause() instanceof ConnectException);
            log.trace("Exception: ", e);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail missing PKI trust connection")
    public void authenticateFailMissingPki() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken());
        auth.getApiClient().setBasePath(CONNECTION().getUrl());

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScope.ACCESSTOKEN);
        } catch (ApiException e) {
            assertTrue(e.getCause() instanceof SSLHandshakeException);
            log.trace("Exception: ", e);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid PEM data")
    public void authenticateFailInvalidCertificate() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken());
        auth.getApiClient().setBasePath(CONNECTION().getUrl());
        log.trace("Initialize REST API client SSL stuff");
        auth.getApiClient().setVerifyingSsl(true);
        log.trace("Taint certificate data to make it invalid");
        assertThrows(IllegalArgumentException.class, () -> auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem().replaceAll("9", "2023"))));
    }
}
