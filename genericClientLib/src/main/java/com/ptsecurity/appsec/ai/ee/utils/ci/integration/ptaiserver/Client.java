package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.rest.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import lombok.Getter;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.TimeUnit;

public class Client extends Base {
    @Getter
    protected final AgentAuthApi authApi = new AgentAuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient());
    @Getter
    protected final ProjectsApi prjApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());
    @Getter
    protected final StoreApi storeApi = new StoreApi(new com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiClient());

    public String init() throws PtaiClientException, PtaiServerException {
        try {
            super.baseInit();
            super.initClients(authApi.getApiClient(), prjApi.getApiClient(), storeApi.getApiClient());

            // Start PT AI EE server negotiation
            ApiResponse<String> authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");
            if (StringUtils.isEmpty(authToken.getData()))
                throw new PtaiClientException("Auth token is empty");

            this.prjApi.getApiClient().setApiKeyPrefix("Bearer");
            this.prjApi.getApiClient().setApiKey(authToken.getData());
            this.storeApi.getApiClient().setApiKeyPrefix("Bearer");
            this.storeApi.getApiClient().setApiKey(authToken.getData());
            return authToken.getData();
        } catch (BaseClientException e) {
            throw new PtaiClientException(e.getMessage(), e);
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
    }
    public void log(com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
        this.log("ApiException thrown with code %d (%s)\r\n", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        super.log(e);
    }
}
