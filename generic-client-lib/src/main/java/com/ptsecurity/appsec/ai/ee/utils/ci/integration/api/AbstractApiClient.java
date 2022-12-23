package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.misc.tools.Jwt;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.EventConsumer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ApiClientHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
@Getter
@RequiredArgsConstructor
public abstract class AbstractApiClient {
    public abstract ScanBrief.ApiVersion getApiVersion();

    @Setter
    protected TextOutput console = null;

    @NonNull
    protected final ConnectionSettings connectionSettings;

    @NonNull
    protected final AdvancedSettings advancedSettings;

    @Setter
    protected EventConsumer eventConsumer = null;

    /**
     * PT AI version-independent API list. This list items are added
     * during instantiation of version-dependent descendant classes
     */
    protected final List<Object> apis = new ArrayList<>();

    /**
     * Currently owned JWT. This jwt token shared by all the APIs and managed by their JwtAuthenticators
     */
    protected Jwt apiJwt = null;

    protected void setApiJwt(@NonNull final Jwt apiJwt) {
        boolean insecure = advancedSettings.getBoolean(AdvancedSettings.SettingInfo.LOGGING_HTTP_CREDENTIALS);
        for (Object api : apis) {
            log.trace("Set JWT {} for {} API", insecure ? apiJwt.getAccessToken() : "${JWT}", api.getClass().toString());
            new ApiClientHelper(api)
                    .setApiKeyPrefix("Bearer")
                    .setApiKey(apiJwt.getAccessToken());
        }
        this.apiJwt = apiJwt;
    }

    public abstract Jwt authenticate() throws GenericException;

    public abstract Map<ServerVersionTasks.Component, String> getCurrentApiVersion() throws GenericException;

    /**
     * Init all PT AI endpoints API clients
     */
    public void init() throws GenericException {
        call(() -> {
            connectionSettings.setUrl(StringUtils.removeEnd(connectionSettings.getUrl().trim(), "/"));
            ApiClientHelper.initApiClient(this);
        }, "API client initialization failed");
    }
}
