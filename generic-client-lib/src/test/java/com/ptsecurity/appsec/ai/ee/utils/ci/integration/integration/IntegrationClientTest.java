package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import org.junit.jupiter.api.Test;

public class IntegrationClientTest {
    @Test
    public void testDiagnosticApi() {
        try {
            Client client = new Client();
            client.setUrl("https://ptai.domain.org:8443");
            client.setClientId("ptai-jenkins-plugin");
            client.setClientSecret("etg76M18UsOGMPLRliwCn2r3g8BlO7TZ");
            client.setUserName("admin");
            client.setPassword("5JBm6YpEcjtDjrCz4wo79lvoV2OLR11U_");
            client.init();
            BuildInfo buildInfo = client.getPublicApi().getBuildInfoUsingGET();
            String buildInfoText = buildInfo.getName() + ".v" + buildInfo.getVersion() + " from " + buildInfo.getDate();
            ComponentsStatus statuses = client.getDiagnosticApi().getComponentsStatusUsingGET();
            String statusText = "PTAI: " + statuses.getPtai() + "; EMBEDDED: " + statuses.getEmbedded();
        } catch (ApiException e) {
            BaseClientException clientException = new BaseClientException("", e);
            clientException.printStackTrace();
            e.printStackTrace();
        }
    }
}
