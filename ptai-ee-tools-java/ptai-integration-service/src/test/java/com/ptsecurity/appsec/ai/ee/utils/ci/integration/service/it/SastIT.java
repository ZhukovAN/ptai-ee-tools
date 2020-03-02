package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.SastService;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@ActiveProfiles("integration-test")
@DisplayName("Test SAST integration service client")
public class SastIT extends BaseIT {

    protected Client client;

    protected String settings = null;
    protected String policy = null;

    @BeforeAll
    public void init() throws IOException {
        ClassLoader cl = getClass().getClassLoader();

        settings = IOUtils.toString(
                cl.getResourceAsStream("json/settings/settings.0.json"),
                StandardCharsets.UTF_8.name());
        policy = IOUtils.toString(
                cl.getResourceAsStream("json/policy/policy.0.json"),
                StandardCharsets.UTF_8.name());
    }

    @BeforeEach
    public void initClient() {
        client = new Client();
        client.setUrl("https://localhost:" + port);
        client.setClientId(clientIdNormal);
        client.setClientSecret(clientSecret);
        client.setUserName(loginTestUser);
        client.setPassword(password);
        client.init();
    }

    @AfterEach
    public void finiClient() {
        client = null;
    }

    @Test
    @DisplayName("Scan UI-managed project")
    public void startUiManagedProjectScan() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("code/test.java.zip").getFile());
        client.uploadZip("DEVEL.TEST.JAVA", file, 50 * 1024);
        Integer scanId = client.getSastApi().scanUiManagedUsingPOST("DEVEL.TEST.JAVA", "ptai");
        System.out.println("SAST job number is " + scanId);

        waitForSastJob(client, scanId);

        List<String> res = client.getSastApi().getJobResultsUsingGET(scanId);
        for (String item : res)
            client.getSastApi().getJobResultUsingGET(scanId, item);
    }

    @Test
    @DisplayName("Scan JSON-managed project")
    public void startJsonManagedProjectScan() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("code/test.java.zip").getFile());
        client.uploadZip("DEVEL.TEST.JAVA", file, 50 * 1024);

        Integer scanId = client.getSastApi().scanJsonManagedUsingPOST("DEVEL.TEST.JAVA", "ptai", settings, policy);
        System.out.println("SAST job number is " + scanId);

        waitForSastJob(client, scanId);

        List<String> res = client.getSastApi().getJobResultsUsingGET(scanId);
        for (String item : res)
            client.getSastApi().getJobResultUsingGET(scanId, item);
    }

    protected void waitForSastJob(Client client, int buildId) throws Exception {
        int pos = 0;
        do {
            JobState state = client.getSastApi().getJobStateUsingGET(buildId, pos);
            if (state.getPos() != pos)
                System.out.print(state.getLog());
            pos = state.getPos();
            if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
            Thread.sleep(1000);
        } while (true);
    }

    @Test
    @DisplayName("Get diagnostic info")
    public void getDiagnosticInfo() throws Exception {
        ComponentsStatus status = client.getDiagnosticApi().getComponentsStatusUsingGET();
        System.out.println(status.toString());
    }


}
