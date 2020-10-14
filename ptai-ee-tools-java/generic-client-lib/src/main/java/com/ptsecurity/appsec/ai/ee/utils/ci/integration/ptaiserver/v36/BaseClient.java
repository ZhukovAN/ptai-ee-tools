package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.AccessTokenScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.AuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.LicenseApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanCompleteEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanEnqueuedEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanProgressEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanStartedEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.ApiClientHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import io.reactivex.Single;
import lombok.*;
import lombok.extern.java.Log;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.joor.Reflect;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.logging.Level;

@Log
public class BaseClient extends Base {
    @Getter
    protected final String id = UUID.randomUUID().toString();

    protected static final int TIMEOUT = 3600 * 1000;

    @Getter
    protected final AuthApi authApi = new AuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiClient());

    @Getter
    protected final ProjectsApi projectsApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final ReportsApi reportsApi = new ReportsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final LicenseApi licenseApi = new LicenseApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final ScanApi scanApi = new ScanApi(new com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.ApiClient());

    @Getter
    protected final ScanAgentApi scanAgentApi = new ScanAgentApi(new com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.ApiClient());

    @Getter
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiClient());

    @Getter
    protected final HealthCheckApi healthCheckApi = new HealthCheckApi(new com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.ApiClient());

    @Getter
    protected final List<Object> apis = new ArrayList<>();

    public BaseClient() {
        super();
        apis.addAll(Arrays.asList(authApi, projectsApi, reportsApi, licenseApi, scanApi, scanAgentApi, storeApi, healthCheckApi));
    }

    /**
     * Currently owned JWT. This JWT token shared by all the APIs and managed by their JwtAuthenticators
     */
    @Getter
    protected JwtResponse JWT = null;

    public void setJWT(@NonNull final JwtResponse JWT) {
        this.JWT = JWT;
        for (Object api : apis) {
            ApiClientHelper helper = new ApiClientHelper(api).init();
            helper.setApiKeyPrefix("Bearer");
            helper.setApiKey(JWT.getAccessToken());
        }
    }

    public JwtResponse authenticate() throws ApiException {
        @NonNull ApiResponse<String> jwt;
        if (null == JWT) {
            authApi.getApiClient().setApiKey(token);
            authApi.getApiClient().setApiKeyPrefix(null);
            jwt = callApi(() ->
                    authApi.apiAuthSigninGetWithHttpInfo(AuthScopeType.ACCESSTOKEN),
                    "JWT authentication call failed");
        } else {
            authApi.getApiClient().setApiKey(null);
            authApi.getApiClient().setApiKeyPrefix(null);
            try {
                jwt = callApi(() -> {
                            Call call = authApi.apiAuthRefreshTokenGetCall(null);
                            Request request = call.request().newBuilder()
                                    .header("Authorization", "Bearer " + JWT.getRefreshToken())
                                    .build();
                            call = authApi.getApiClient().getHttpClient().newCall(request);
                            return authApi.getApiClient().execute(call, new TypeToken<String>() {
                            }.getType());
                        },
                        "JWT refresh call failed");
            } catch (ApiException e) {
                authApi.getApiClient().setApiKey(token);
                authApi.getApiClient().setApiKeyPrefix(null);
                jwt = callApi(() ->
                        authApi.apiAuthSigninGetWithHttpInfo(AuthScopeType.ACCESSTOKEN),
                        "JWT authentication call failed");
            }
        }

        final String jwtData = jwt.getData();

        @NonNull JwtResponse res = callApi(() ->
                new ObjectMapper().readValue(jwtData, JwtResponse.class),
                "JWT parse failed");
        // JwtResponse's refreshToken field is null after refresh, let's fill it
        // to avoid multiple parsing calls
        if (StringUtils.isEmpty(res.getRefreshToken()))
            res.setRefreshToken(JWT.getRefreshToken());
        log.finest("JWT: " + res);
        setJWT(res);

        return res;
    }

    @Getter
    protected String url = "";

    public void setUrl(@NonNull final String url) {
        this.url = StringUtils.removeEnd(url.trim(), "/");
    }

    @Setter
    @Getter
    @NonNull
    protected String token = null;

    @Getter
    @Setter
    protected int timeout = TIMEOUT;

    /**
     * PEM-encoded CA certificate chain
     */
    @Setter
    @Getter
    @NonNull
    protected String caCertsPem = "";

    public void init() {
        ApiClientHelper.initClientApis(this, apis);
    }

    @SneakyThrows
    public void setCaCertsJks(@NonNull final Path jks) {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(jks.toFile()), "".toCharArray());
        caCertsPem = CertificateHelper.trustStoreToPem(keyStore);
    }

    protected static <V> V callApi(Callable<V> call, String errorMessage) throws ApiException {
        try {
            return call.call();
        } catch (Exception e) {
            throw ApiException.raise(errorMessage, e);
        }
    }

    /**
     * Need to implement our own Runnable that throws checked Exception
     */
    @FunctionalInterface
    public interface Runnable {
        void run() throws Exception;
    }

    public static void callApi(Runnable call, String errorMessage) throws ApiException {
        callApi(() -> {
            call.run();
            return null;
        }, errorMessage);
    }


    protected String connectedDate = "";

    @SneakyThrows
    protected HubConnection createSignalrConnection(
            @NonNull final UUID scanResultId) {
        // Create accessTokenProvider to provide SignalR connection
        // with JWT
        Single<String> accessTokenProvider = Single.defer(() -> {
            return Single.just(getJWT().getAccessToken());
        });

        HubConnection connection = HubConnectionBuilder.create(url + "/notifyApi/notifications?clientId=" + id)
                .withAccessTokenProvider(accessTokenProvider)
                .withHeader("connectedDate", connectedDate)
                .build();
        if (StringUtils.isNotEmpty(caCertsPem)) {
            // Here goes a lot of reflections to setup custom CA certificate chain
            //
            // Create in-memory keystore and fill it with caCertsPem data
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            List<X509Certificate> certs = CertificateHelper.readPem(caCertsPem);
            for (X509Certificate cert : certs)
                keyStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
            // Init trustManagerFactory with custom CA certificates
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new SecureRandom());
            // Modify default settings
            Object httpClient = Reflect.on(connection).get("httpClient");
            OkHttpClient okHttpClient = Reflect.on(httpClient).get("client");
            okHttpClient = okHttpClient.newBuilder()
                    .hostnameVerifier((hostname, session) -> true)
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagers[0])
                    .build();
            Reflect.on(httpClient).set("client", okHttpClient);
        }

        // Register subscriptions
        connection.on("NeedUpdateConnectedDate", (message) -> {
            log.finest("NeedUpdateConnectedDate: " + message);
            connectedDate = message;
        }, String.class);

        connection.on("NeedRefreshToken", (data) -> {
            log.finest("NeedRefreshToken");
            authenticate();
        }, String.class);

        connection.on("NeedSyncClientState", () -> {
            log.finest("NeedSyncClientState");
            subscribe(connection, scanResultId);
        });

        connection.on("ScanStarted", (data) -> {
            info("Scan started");
        }, ScanStartedEvent.class);

        connection.on("ScanProgress", (data) -> {
            String message = data.getProgress().getStage().toString();
            if (null != data.getProgress().getSubStage())
                message += " -> " + data.getProgress().getSubStage() + "";
            message += " " + data.getProgress().getValue() + "%";
            info(message);
        }, ScanProgressEvent.class);

        connection.on("ScanEnqueued", (data) -> {
            info("Scan enqueued");
        }, ScanEnqueuedEvent.class);

        return connection;
    }

    @RequiredArgsConstructor
    private final class SubscriptionOnNotification {
        @Getter @Setter
        public String ClientId;

        @Getter @Setter
        public String NotificationTypeName;

        @Getter @Setter
        public Set<UUID> Ids = new HashSet<>();

        @Getter
        public final Date CreatedDate;

        public SubscriptionOnNotification() {
            this.CreatedDate = new Date();
        }
    }

    protected void subscribe(
            @NonNull final HubConnection connection,
            @NonNull final UUID scanResultId) {
        SubscriptionOnNotification subscription = new SubscriptionOnNotification();
        subscription.setClientId(id);
        subscription.getIds().add(scanResultId);

        subscription.setNotificationTypeName("ScanEnqueued");
        connection.send("SubscribeOnNotification", subscription);

        subscription.setNotificationTypeName("ScanStarted");
        connection.send("SubscribeOnNotification", subscription);

        subscription.setNotificationTypeName("ScanProgress");
        connection.send("SubscribeOnNotification", subscription);

        subscription.setNotificationTypeName("ScanCompleted");
        connection.send("SubscribeOnNotification", subscription);
    }
}
