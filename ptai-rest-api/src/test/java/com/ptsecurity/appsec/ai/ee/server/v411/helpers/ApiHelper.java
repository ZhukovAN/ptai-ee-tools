package com.ptsecurity.appsec.ai.ee.server.v411.helpers;

import com.ptsecurity.appsec.ai.ee.server.helpers.AbstractApiHelper;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.api.AuthApi;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.AuthResultModel;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.server.v411.auth.model.UserLoginModel;
import com.ptsecurity.appsec.ai.ee.server.v411.filesstore.api.StoreApi;
import com.ptsecurity.appsec.ai.ee.server.v411.legacy.api.VersionApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.LicenseApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.api.ReportsApi;
import com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.api.ScanQueueApi;
import com.ptsecurity.appsec.ai.ee.server.v411.systemmanagement.api.HealthCheckApi;
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

    public final static AuthApi AUTH = new AuthApi(new com.ptsecurity.appsec.ai.ee.server.v411.auth.ApiClient());
    public final static ProjectsApi PROJECTS = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());
    public final static LicenseApi LICENSE = new LicenseApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());
    public final static VersionApi VERSION = new VersionApi(new com.ptsecurity.appsec.ai.ee.server.v411.legacy.ApiClient());
    public final static StoreApi STORE = new StoreApi(new com.ptsecurity.appsec.ai.ee.server.v411.filesstore.ApiClient());
    public final static ScanQueueApi QUEUE = new ScanQueueApi(new com.ptsecurity.appsec.ai.ee.server.v411.scanscheduler.ApiClient());
    public final static HealthCheckApi HEALTH = new HealthCheckApi(new com.ptsecurity.appsec.ai.ee.server.v411.systemmanagement.ApiClient());
    public final static ReportsApi REPORTS = new ReportsApi(new com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.ApiClient());

    static {
        API.addAll(Arrays.asList(AUTH, PROJECTS, LICENSE, VERSION, STORE, QUEUE, HEALTH, REPORTS));
    }
}
