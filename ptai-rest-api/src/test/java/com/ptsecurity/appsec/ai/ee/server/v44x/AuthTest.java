package com.ptsecurity.appsec.ai.ee.server.v44x;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.Environment;
import com.ptsecurity.appsec.ai.ee.server.v44x.auth.ApiClient;
import com.ptsecurity.appsec.ai.ee.server.v44x.auth.ApiException;
import com.ptsecurity.appsec.ai.ee.server.v44x.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v44x.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v44x.auth.model.AuthScopeType;
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
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V44X;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.misc.tools.helpers.CertificateHelper.createTrustManager;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@Tag("integration")
@Environment(enabledFor = { V44X })
@DisplayName("Test PT AI 4.4.X authentication calls")
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

        AuthResultModel authResult = assertDoesNotThrow(() -> auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN));
        log.trace("Authentication result: {}", authResult);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid token connection")
    public void authenticateFailInvalidToken() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID().toString());
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
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
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
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID().toString());
        auth.getApiClient().setBasePath("https://" + UUID.randomUUID().toString());
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
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
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

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
        } catch (ApiException e) {
            assertTrue(e.getCause() instanceof SocketTimeoutException);
            log.trace("Exception: ", e);
        }
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

        try {
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
        } catch (ApiException e) {
            assertEquals(HttpStatus.SC_NOT_FOUND, e.getCode());
            log.trace("Exception: ", e);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid port connection")
    public void authenticateFailInvalidPort() {
        AuthApi auth = new AuthApi(new ApiClient());

        auth.getApiClient().setApiKeyPrefix(null);
        auth.getApiClient().setApiKey(CONNECTION().getToken() + UUID.randomUUID().toString());
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
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
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
            AuthResultModel authResult = auth.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN);
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
        assertThrows(CertificateException.class, () -> auth.getApiClient().setSslCaCert(CertificateHelper.cleanupCaPem(CONNECTION().getCaPem().replaceAll("9", "2023"))));
    }
}
