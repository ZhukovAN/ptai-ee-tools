package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.EventConsumer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ApiClientHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Getter
@RequiredArgsConstructor
public abstract class AbstractApiClient {
    @Setter
    protected TextOutput console;

    @NonNull
    protected final ConnectionSettings connectionSettings;

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
    protected JwtResponse apiJwt = null;

    protected void setApiJwt(@NonNull final JwtResponse apiJwt) {
        for (Object api : apis)
            new ApiClientHelper(api)
                    .setApiKeyPrefix("Bearer")
                    .setApiKey(apiJwt.getAccessToken());
        this.apiJwt = apiJwt;
    }

    public abstract JwtResponse authenticate() throws GenericException;

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
