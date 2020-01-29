package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.AdminControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.DiagnosticControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.PublicControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.SastControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils.JwtAuthenticator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import lombok.Getter;
import lombok.Setter;
import okhttp3.OkHttpClient;

@Getter @Setter
public class Client extends BaseClient {
    protected final SastControllerApi sastApi = new SastControllerApi(new ApiClient());
    protected final AdminControllerApi adminApi = new AdminControllerApi(new ApiClient());
    protected final PublicControllerApi publicApi = new PublicControllerApi(new ApiClient());
    protected final DiagnosticControllerApi diagnosticApi = new DiagnosticControllerApi(new ApiClient());

    protected String userName = null;
    protected String password = null;
    protected String clientId = null;
    protected String clientSecret = null;

    protected JwtResponse jwt = null;

    public void init() throws PtaiClientException {
        super.baseInit();
        super.initClients(sastApi, adminApi, publicApi, diagnosticApi);
    }

    @Override
    protected void initClient(Object client) throws BaseClientException {
        super.initClient(client);

        ApiClientHelper helper = new ApiClientHelper(client).init();
        OkHttpClient httpClient = helper.getHttpClient();
        httpClient = httpClient.newBuilder()
                .authenticator(new JwtAuthenticator(client, url, clientId, clientSecret, userName, password))
                .build();
        helper.setHttpClient(httpClient);
    }
}