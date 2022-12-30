package com.ptsecurity.appsec.ai.ee.server.v420.helpers;

import com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper;
import com.ptsecurity.appsec.ai.ee.server.v420.api.ApiClient;
import com.ptsecurity.appsec.ai.ee.server.v420.api.api.*;
import com.ptsecurity.appsec.ai.ee.server.v420.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v420.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v420.auth.model.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.server.v420.auth.model.UserLoginModel;
import com.ptsecurity.misc.tools.Jwt;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType.CI;
import static com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper.TokenType.ROOT;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Slf4j
public class ApiHelper extends AbstractApiHelper {
    @Override
    public void authenticate() {
        for (TokenType tokenType : TokenType.values()) {
            AUTH.getApiClient().setBasePath(CONNECTION().getUrl());
            AUTH.getApiClient().setVerifyingSsl(false);
            AuthResultModel authResult;
            if (ROOT == tokenType) {
                UserLoginModel model = new UserLoginModel();
                model.setLogin(CONNECTION().getUser());
                model.setPassword(CONNECTION().getPassword());
                authResult = assertDoesNotThrow(() -> AUTH.apiAuthUserLoginPost(AuthScopeType.WEB, model));
            } else {
                AUTH.getApiClient().setApiKeyPrefix(null);
                if (CI == tokenType)
                    AUTH.getApiClient().setApiKey(CONNECTION().getToken());
                else
                    AUTH.getApiClient().setApiKey(CONNECTION().getFailSafeToken());
                authResult = assertDoesNotThrow(() -> AUTH.apiAuthSigninGet(AuthScopeType.ACCESSTOKEN));
            }
            log.trace("Successful authentication for {} token", tokenType);
            JWT.put(tokenType, new Jwt(authResult.getAccessToken(), authResult.getRefreshToken(), authResult.getExpiredAt()));
        }
    }

    public final static AuthApi AUTH = new AuthApi(new com.ptsecurity.appsec.ai.ee.server.v420.auth.ApiClient());
    public final static ProjectsApi PROJECTS = new ProjectsApi(new ApiClient());
    public final static LicenseApi LICENSE = new LicenseApi(new ApiClient());
    public final static VersionApi VERSION = new VersionApi(new ApiClient());
    public final static StoreApi STORE = new StoreApi(new ApiClient());
    public final static ScanQueueApi QUEUE = new ScanQueueApi(new ApiClient());
    public final static HealthCheckApi HEALTH = new HealthCheckApi(new ApiClient());
    public final static ReportsApi REPORTS = new ReportsApi(new ApiClient());

    static {
        API.addAll(Arrays.asList(AUTH, PROJECTS, LICENSE, VERSION, STORE, QUEUE, HEALTH, REPORTS));
    }
}
