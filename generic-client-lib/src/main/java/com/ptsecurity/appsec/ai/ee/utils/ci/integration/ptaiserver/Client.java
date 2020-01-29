package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.ptai.server.auth.rest.AuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.rest.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

public class Client extends BaseClient {
    @Getter
    protected final AgentAuthApi agentAuthApi = new AgentAuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient());

    @Getter
    protected final ProjectsApi prjApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

    @Getter
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiClient());

    @Getter
    protected final AuthApi authApi = new AuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiClient());

    public String init() throws PtaiClientException {
        return init(true);
    }

    public String init(boolean authenticate) throws PtaiClientException {
        super.baseInit();
        super.initClients(agentAuthApi, prjApi, storeApi, authApi);
        return authenticate ? signIn() : "";
    }

    public String signIn() throws PtaiClientException {
        try {
            // Start PT AI EE server negotiation
            ApiResponse<String> authToken = agentAuthApi.signInWithHttpInfo("Agent");
            if (StringUtils.isEmpty(authToken.getData()))
                throw new PtaiClientException("Auth token is empty");

            this.prjApi.getApiClient().setApiKeyPrefix("Bearer");
            this.prjApi.getApiClient().setApiKey(authToken.getData());
            this.storeApi.getApiClient().setApiKeyPrefix("Bearer");
            this.storeApi.getApiClient().setApiKey(authToken.getData());
            this.authApi.getApiClient().setApiKeyPrefix("Bearer");
            this.authApi.getApiClient().setApiKey(authToken.getData());
            return authToken.getData();
        } catch (BaseClientException e) {
            throw new PtaiClientException("PT AI EE server login failed", e);
        } catch (ApiException e) {
            throw new PtaiServerException("PT AI EE server login failed", e);
        }
    }

    public void log(com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
        this.log("ApiException thrown. %s\r\n", BaseClientException.getInnerExceptionDetails(e));
        super.log(e);
    }
}
