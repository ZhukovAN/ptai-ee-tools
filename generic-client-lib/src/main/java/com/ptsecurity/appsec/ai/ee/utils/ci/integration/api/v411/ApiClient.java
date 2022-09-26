package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411;

import com.google.gson.reflect.TypeToken;
import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.UserLoginModel;
import com.ptsecurity.appsec.ai.ee.server.v411.filesstore.api.StoreApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ConfigsApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.LicenseApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ReportsApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ScanProgress;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ScanProgressModel;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.Stage;
import com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.api.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.api.ScanQueueApi;
import com.ptsecurity.appsec.ai.ee.server.v411.systemmanagement.api.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.server.v411.updateserver.api.VersionApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.VersionRange;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters.EnumsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events.ScanCompleteEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events.ScanProgressEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events.ScanResultRemovedEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.events.ScanStartedEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.tasks.ServerVersionTasksImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ApiClientHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.LoggingInterceptor;
import io.reactivex.rxjava3.core.Single;
import lombok.*;
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
import java.lang.reflect.Type;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.BlockingQueue;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@VersionRange(min = { 4, 1, 0, 0 }, max = { 4, 1, 0, 99999 })
public class ApiClient extends AbstractApiClient {
    @Getter
    protected final String id = UUID.randomUUID().toString();

    @Getter
    @ToString.Exclude
    protected final AuthApi authApi = new AuthApi(new com.ptsecurity.appsec.ai.ee.server.v411.auth.ApiClient());

    @Getter
    @ToString.Exclude
    protected final com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ProjectsApi projectsApi = new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ProjectsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ReportsApi reportsApi = new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ReportsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ConfigsApi configsApi = new ConfigsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ReportsApi legacyReportsApi = new ReportsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final LicenseApi licenseApi = new LicenseApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ScanQueueApi scanQueueApi = new ScanQueueApi(new com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.ApiClient());

    @Getter
    @ToString.Exclude
    protected final ScanAgentApi scanAgentApi = new ScanAgentApi(new com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.ApiClient());

    @Getter
    @ToString.Exclude
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.server.v411.filesstore.ApiClient());

    @Getter
    @ToString.Exclude
    protected final HealthCheckApi healthCheckApi = new HealthCheckApi(new com.ptsecurity.appsec.ai.ee.server.v411.systemmanagement.ApiClient());

    @Getter
    @ToString.Exclude
    protected final VersionApi versionApi = new VersionApi(new com.ptsecurity.appsec.ai.ee.server.v411.updateserver.ApiClient());

    public ApiClient(@NonNull final ConnectionSettings connectionSettings) {
        super(connectionSettings, AdvancedSettings.getDefault());
        apis.addAll(Arrays.asList(authApi, projectsApi, configsApi, reportsApi, legacyReportsApi, licenseApi, scanQueueApi, scanAgentApi, storeApi, healthCheckApi, versionApi));
    }

    public ApiClient(@NonNull final ConnectionSettings connectionSettings, @NonNull final AdvancedSettings advancedSettings) {
        super(connectionSettings, advancedSettings);
        apis.addAll(Arrays.asList(authApi, projectsApi, configsApi, reportsApi, legacyReportsApi, licenseApi, scanQueueApi, scanAgentApi, storeApi, healthCheckApi, versionApi));
    }

    protected ApiResponse<AuthResultModel> initialAuthentication() throws GenericException {
        BaseCredentials baseCredentials = connectionSettings.getCredentials();
        if (baseCredentials instanceof TokenCredentials) {
            log.trace("Using PT AI API token-based credentials for authentication");
            TokenCredentials tokenCredentials = (TokenCredentials) baseCredentials;
            authApi.getApiClient().setApiKey(tokenCredentials.getToken());
            authApi.getApiClient().setApiKeyPrefix(null);
            log.trace("Calling auth/signin endpoint with API token");
            return call(
                    () -> authApi.apiAuthSigninGetWithHttpInfo(AuthScopeType.ACCESSTOKEN),
                    "Get initial JWT call failed");
        } else {
            log.trace("Using PT AI API password-based credentials for authentication");
            PasswordCredentials passwordCredentials = (PasswordCredentials) baseCredentials;

            UserLoginModel model = new UserLoginModel();
            model.setLogin(passwordCredentials.getUser());
            model.setPassword(passwordCredentials.getPassword());
            log.trace("Calling auth/userLogin endpoint with user name and password");
            return call(
                    () -> authApi.apiAuthUserLoginPostWithHttpInfo(AuthScopeType.WEB, model),
                    "Get initial JWT call failed");
        }
    }

    @Override
    public ScanBrief.ApiVersion getApiVersion() {
        return ScanBrief.ApiVersion.V411;
    }

    public JwtResponse authenticate() throws GenericException {
        @NonNull
        ApiResponse<AuthResultModel> jwtResponse;

        if (null == this.apiJwt) {
            // We have no JWT yet, so need to get it using token-based authentication
            log.trace("We have no JWT yet, so need to get it using token- or password-based authentication");
            jwtResponse = initialAuthentication();
        } else {
            // We already have JWT, but it might be expired. Try to refresh it
            log.trace("Authentication called and we already have JWT. Let's refresh it");
            authApi.getApiClient().setApiKey(null);
            authApi.getApiClient().setApiKeyPrefix(null);

            try {
                jwtResponse = call(
                        () -> {
                            // Need to replace authApi call token to refresh one
                            log.trace("Call auth/refreshToken endpoint with existing JWT refresh token");
                            Call call = authApi.apiAuthRefreshTokenGetCall(null);
                            Request request = call.request().newBuilder()
                                    .header("Authorization", "Bearer " + this.apiJwt.getRefreshToken())
                                    .build();
                            call = authApi.getApiClient().getHttpClient().newCall(request);
                            final Type stringType = new TypeToken<AuthResultModel>() {}.getType();
                            return authApi.getApiClient().execute(call, stringType);
                        },
                        "Refresh JWT call failed");
                log.trace("JWT token refreshed: {}", jwtResponse);
            } catch (GenericException e) {
                // Exception thrown while trying to refresh JWT. Let's re-authenticate using API token
                log.trace("JWT refresh failed, let's authenticate using initial credentials");
                jwtResponse = initialAuthentication();
                log.trace("JWT token after re-authentication: {}", jwtResponse);
            }
        }

        // Parse JWT from response string
        final AuthResultModel jwtData = jwtResponse.getData();
        @NonNull
        JwtResponse res = new JwtResponse(
                jwtData.getAccessToken(),
                jwtData.getRefreshToken(),
                Objects.requireNonNull(jwtData.getExpiredAt()).toString());
        log.trace("JWT parse result: {}", res);
        // JwtResponse's refreshToken field is null after refresh, let's fill it
        // to avoid multiple parsing calls
        if (StringUtils.isEmpty(res.getRefreshToken()))
            res.setRefreshToken(this.apiJwt.getRefreshToken());
        // Store new JWT and set it as Bearer API key to all APIs
        setApiJwt(res);
        log.trace("JWT: " + res);

        return res;
    }

    @Override
    public Map<ServerVersionTasks.Component, String> getCurrentApiVersion() throws GenericException {
        return new ServerVersionTasksImpl(this).current();
    }

    @ToString.Exclude
    protected String connectedDate = "";

    public HubConnection createSignalrConnection(@NonNull UUID projectId, @NonNull final UUID scanResultId, final BlockingQueue<Stage> queue) throws GenericException {
        // Create accessTokenProvider to provide SignalR connection
        // with jwt
        Single<String> accessTokenProvider = Single.defer(() -> Single.just(apiJwt.getAccessToken()));

        final HubConnection connection = HubConnectionBuilder.create(connectionSettings.getUrl() + "/notifyApi/notifications?clientId=" + id)
                .withAccessTokenProvider(accessTokenProvider)
                .withHeader("connectedDate", connectedDate)
                .build();
        log.trace("HubConnection created with id = " + id);

        X509TrustManager trustManager = ApiClientHelper.createTrustManager(connectionSettings.getCaCertsPem(), connectionSettings.isInsecure());

        Object httpClient = Reflect.on(connection).get("httpClient");
        OkHttpClient okHttpClient = Reflect.on(httpClient).get("client");
        OkHttpClient.Builder httpBuilder = okHttpClient.newBuilder();
        httpBuilder
                .hostnameVerifier((hostname, session) -> true)
                .addInterceptor(new LoggingInterceptor(advancedSettings))
                .protocols(Collections.singletonList(Protocol.HTTP_1_1));
        if (null != trustManager) {
            SSLContext sslContext = call(() -> SSLContext.getInstance("TLS"), "SSL context creation failed");
            call(() -> sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom()), "SSL context initialization failed");
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
            subscribe(connection, projectId, scanResultId);
        });

        connection.on("ScanStarted", (data) -> {
            if (!projectId.equals(data.getResult().getProjectId()))
                log.trace("Skip ScanStarted event as its projectId != {}", projectId);
            else if (!scanResultId.equals(data.getResult().getId()))
                log.trace("Skip ScanStarted event as its scanResultId != {}", scanResultId);
            else {
                if (null != console)
                    console.info("Scan started. Project id: %s, scan result id: %s", data.getResult().getProjectId(), data.getResult().getId());
                if (null != eventConsumer) eventConsumer.process(data);
            }
            log.trace(data.toString());
        }, ScanStartedEvent.class);

        // Currently PT AI viewer have no stop scan feature but deletes scan result
        connection.on("ScanResultRemoved", (data) -> {
            if (!scanResultId.equals(data.getScanResultId())) return;
            if (null != console) console.info("Scan result removed. Possibly job was terminated from PT AI viewer");
            if (null != eventConsumer) eventConsumer.process(com.ptsecurity.appsec.ai.ee.scan.progress.Stage.ABORTED);
            log.trace(data.toString());
            if (null != queue) {
                log.debug("Scan result {} removed", scanResultId);
                queue.add(Stage.ABORTED);
            }
        }, ScanResultRemovedEvent.class);

        connection.on("ScanProgress", (data) -> {
            if (!scanResultId.equals(data.getScanResultId()))
                log.trace("Skip ScanProgress event as its projectId != {}", projectId);
            else {
                StringBuilder builder = new StringBuilder();
                builder.append(Optional.of(data)
                        .map(ScanProgressEvent::getProgress)
                        .map(ScanProgressModel::getStage)
                        .map(Stage::getValue)
                        .orElse("data.progress.stage missing"));
                Optional.of(data)
                        .map(ScanProgressEvent::getProgress)
                        .map(ScanProgressModel::getSubStage)
                        .ifPresent(s -> builder.append(" -> ").append(s));
                Optional.of(data)
                        .map(ScanProgressEvent::getProgress)
                        .map(ScanProgressModel::getValue)
                        .ifPresent(s -> builder.append(" ").append(s).append("%"));
                if (null != console) console.info(builder.toString());
                // Failed or aborted scans do not generate ScanCompleted event but
                // send ScanProgress event with stage failed or aborted
                Optional<Stage> stage = Optional.of(data)
                        .map(ScanProgressEvent::getProgress)
                        .map(ScanProgressModel::getStage);
                if (stage.isPresent()) {
                    if (null != eventConsumer) eventConsumer.process(EnumsConverter.convert(stage.get()));
                    if (null != queue && (Stage.ABORTED == stage.get() || Stage.FAILED == stage.get())) {
                        if (null != console) console.info("Scan job was terminated with state " + stage.get());
                        log.debug("ScanProgressEvent stage {} is to be put to AST task queue", stage.get());
                        queue.add(stage.get());
                    }
                }
            }
            log.trace(data.toString());
        }, ScanProgressEvent.class);

        connection.on("ScanCompleted", (data) -> {
            if (!projectId.equals(data.getResult().getProjectId()))
                log.trace("Skip ScanCompleted event as its projectId != {}", projectId);
            else if (!scanResultId.equals(data.getResult().getId()))
                log.trace("Skip ScanCompleted event as its scanResultId != {}", scanResultId);
            else
                queue.add(Stage.DONE);
            log.trace(data.toString());
        }, ScanCompleteEvent.class);

        return connection;
    }

    public void wait(@NonNull final HubConnection connection, @NonNull UUID projectId, @NonNull final UUID scanResultId) {
        connection.start().doOnComplete(() -> subscribe(connection, projectId, scanResultId)).blockingAwait();
    }

    @Getter
    @Setter
    @RequiredArgsConstructor
    private static final class SubscriptionOnNotification {
        private String ClientId;

        private String NotificationTypeName;

        private Set<UUID> Ids = new HashSet<>();

        private final Date CreatedDate;

        SubscriptionOnNotification() {
            this.CreatedDate = new Date();
        }
    }

    protected void subscribe(
            @NonNull final HubConnection connection,
            @NonNull UUID projectId,
            @NonNull final UUID scanResultId) {
        SubscriptionOnNotification subscription = new SubscriptionOnNotification();
        subscription.ClientId = id;
        // subscription.Ids.add(scanResultId);

        subscription.NotificationTypeName = "ScanStarted";
        connection.send("SubscribeOnNotification", subscription);

        subscription.NotificationTypeName = "ScanProgress";
        connection.send("SubscribeOnNotification", subscription);

        subscription.NotificationTypeName = "ScanCompleted";
        connection.send("SubscribeOnNotification", subscription);

        // ScanResultRemoved event subscription uses projectId-based filtering
        subscription.Ids.clear();
        subscription.Ids.add(projectId);
        subscription.NotificationTypeName = "ScanResultRemoved";
        connection.send("SubscribeOnNotification", subscription);
    }
}
