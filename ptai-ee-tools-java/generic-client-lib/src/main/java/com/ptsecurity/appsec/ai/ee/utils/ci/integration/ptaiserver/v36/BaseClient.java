package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.AuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.updateserver.v36.VersionApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.ApiClientHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.LoggingInterceptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanProgressEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanStartedEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtResponse;
import io.reactivex.Single;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;
import org.joor.Reflect;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.util.*;

@Slf4j
@SuperBuilder
@NoArgsConstructor
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
    protected final VersionApi versionApi = new VersionApi(new com.ptsecurity.appsec.ai.ee.ptai.server.updateserver.ApiClient());

    @Getter
    protected final List<Object> apis = Arrays.asList(authApi, projectsApi, reportsApi, licenseApi, scanApi, scanAgentApi, storeApi, healthCheckApi, versionApi);

    /**
     * Currently owned jwt. This jwt token shared by all the APIs and managed by their JwtAuthenticators
     */
    @Getter
    @Builder.Default
    protected JwtResponse jwt = null;

    public BaseClient jwt(@NonNull final JwtResponse jwt) {
        this.jwt = jwt;
        for (Object api : apis)
            new ApiClientHelper(api)
                    .init()
                    .setApiKeyPrefix("Bearer")
                    .setApiKey(jwt.getAccessToken());
        return this;
    }

    public JwtResponse authenticate() throws ApiException {
        @NonNull ApiResponse<String> jwt;
        if (null == this.jwt) {
            authApi.getApiClient().setApiKey(token);
            authApi.getApiClient().setApiKeyPrefix(null);
            jwt = callApi(() ->
                    authApi.apiAuthSigninGetWithHttpInfo(AuthScopeType.ACCESSTOKEN),
                    "jwt authentication call failed");
        } else {
            authApi.getApiClient().setApiKey(null);
            authApi.getApiClient().setApiKeyPrefix(null);
            try {
                jwt = callApi(() -> {
                            Call call = authApi.apiAuthRefreshTokenGetCall(null);
                            Request request = call.request().newBuilder()
                                    .header("Authorization", "Bearer " + this.jwt.getRefreshToken())
                                    .build();
                            call = authApi.getApiClient().getHttpClient().newCall(request);
                            return authApi.getApiClient().execute(call, new TypeToken<String>() {
                            }.getType());
                        },
                        "jwt refresh call failed");
            } catch (ApiException e) {
                authApi.getApiClient().setApiKey(token);
                authApi.getApiClient().setApiKeyPrefix(null);
                jwt = callApi(() ->
                        authApi.apiAuthSigninGetWithHttpInfo(AuthScopeType.ACCESSTOKEN),
                        "jwt authentication call failed");
            }
        }

        final String jwtData = jwt.getData();

        @NonNull JwtResponse res = callApi(() ->
                new ObjectMapper().readValue(jwtData, JwtResponse.class),
                "jwt parse failed");
        // JwtResponse's refreshToken field is null after refresh, let's fill it
        // to avoid multiple parsing calls
        if (StringUtils.isEmpty(res.getRefreshToken()))
            res.setRefreshToken(this.jwt.getRefreshToken());
        log.trace("jwt: " + res);
        jwt(res);

        return res;
    }

    /**
     * PT AI server URL
     */
    @Getter
    @Setter
    protected String url;

    /**
     * PT AI server API token
     */
    @Setter
    @Getter
    protected String token;

    /**
     * PT AI API client timeout
     */
    @Getter
    @Setter
    @Builder.Default
    protected int timeout = TIMEOUT;

    /**
     * PEM-encoded CA certificate chain. If null or empty then
     * JRE cacerts-defined CA certificates are used only
     */
    @Setter
    @Getter
    protected String caCertsPem;

    @Getter
    @Setter
    @Builder.Default
    protected boolean insecure = false;

    @Builder.Default
    private boolean initialized = false;

    @Getter
    @Setter
    @Builder.Default
    protected ScanType scanType = ScanType.FULL;

    /**
     * Init all PT AI endpoints API clients
     */
    public boolean init() {
        try {
            return unsafeInit();
        } catch (ApiException e) {
            warning(e);
            return false;
        }
    }

    public boolean unsafeInit() throws ApiException {
        url = StringUtils.removeEnd(url.trim(), "/");
        ApiClientHelper.initClientApis(this, apis);
        initialized = true;
        return true;
    }

    @Builder.Default
    protected String connectedDate = "";

    @SneakyThrows
    HubConnection createSignalrConnection(
            @NonNull final UUID scanResultId) {
        // Create accessTokenProvider to provide SignalR connection
        // with jwt
        Single<String> accessTokenProvider = Single.defer(() -> Single.just(jwt.getAccessToken()));

        final HubConnection connection = HubConnectionBuilder.create(url + "/notifyApi/notifications?clientId=" + id)
                .withAccessTokenProvider(accessTokenProvider)
                .withHeader("connectedDate", connectedDate)
                .build();
        log.trace("HubConnection created with id = " + id);

        X509TrustManager trustManager = ApiClientHelper.createTrustManager(caCertsPem, insecure);

        Object httpClient = Reflect.on(connection).get("httpClient");
        OkHttpClient okHttpClient = Reflect.on(httpClient).get("client");
        OkHttpClient.Builder httpBuilder = okHttpClient.newBuilder();
        httpBuilder
                .hostnameVerifier((hostname, session) -> true)
                .addInterceptor(new LoggingInterceptor())
                .protocols(Arrays.asList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
            httpBuilder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }
        Reflect.on(httpClient).set("client", httpBuilder.build());

        // Register subscriptions
        connection.on("NeedUpdateConnectedDate", (message) -> {
            log.trace("Event:NeedUpdateConnectedDate: " + message);
            connectedDate = message;
        }, String.class);

        connection.on("NeedRefreshToken", () -> {
            log.trace("Event:NeedRefreshToken");
            authenticate();
        });

        connection.on("NeedSyncClientState", () -> {
            log.trace("Event:NeedSyncClientState");
            subscribe(connection, scanResultId);
        });

        connection.on("ScanStarted", (data) -> {
            info("Scan started");
            log.trace(data.toString());
        }, ScanStartedEvent.class);

        connection.on("ScanProgress", (data) -> {
            StringBuilder builder = new StringBuilder();
            builder.append(Optional.of(data)
                    .map(ScanProgressEvent::getProgress)
                    .map(ScanProgress::getStage)
                    .map(Stage::getValue)
                    .orElse("data.progress.stage missing"));
            Optional.of(data)
                    .map(ScanProgressEvent::getProgress)
                    .map(ScanProgress::getSubStage)
                    .ifPresent(s -> builder.append(" -> ").append(s));
            Optional.of(data)
                    .map(ScanProgressEvent::getProgress)
                    .map(ScanProgress::getValue)
                    .ifPresent(s -> builder.append(" ").append(s).append("%"));
            info(builder.toString());
            log.trace(data.toString());
        }, ScanProgressEvent.class);

        return connection;
    }

    @RequiredArgsConstructor
    private final class SubscriptionOnNotification {
        @Getter
        @Setter
        private String ClientId;

        @Getter @Setter
        private String NotificationTypeName;

        @Getter @Setter
        private Set<UUID> Ids = new HashSet<>();

        @Getter
        private final Date CreatedDate;

        SubscriptionOnNotification() {
            this.CreatedDate = new Date();
        }
    }

    protected void subscribe(
            @NonNull final HubConnection connection,
            @NonNull final UUID scanResultId) {
        SubscriptionOnNotification subscription = new SubscriptionOnNotification();
        subscription.ClientId = id;
        subscription.Ids.add(scanResultId);

        subscription.NotificationTypeName = "ScanEnqueued";
        connection.send("SubscribeOnNotification", subscription);

        subscription.NotificationTypeName = "ScanStarted";
        connection.send("SubscribeOnNotification", subscription);

        subscription.NotificationTypeName = "ScanProgress";
        connection.send("SubscribeOnNotification", subscription);

        subscription.NotificationTypeName = "ScanCompleted";
        connection.send("SubscribeOnNotification", subscription);
    }
}
