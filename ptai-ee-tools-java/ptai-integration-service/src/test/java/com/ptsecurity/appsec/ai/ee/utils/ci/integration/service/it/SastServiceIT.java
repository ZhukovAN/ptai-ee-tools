package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.JwtRestTemplateBaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.SastService;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc(printOnlyOnFailure = false)
@ActiveProfiles("integration-test")
@DisplayName("Test SAST job execution")
public class SastServiceIT extends JwtRestTemplateBaseIT {
    protected final static String apiSastUpload = "/api/sast/upload";
    protected final static String apiSastScanUiManaged = "/api/sast/scan-ui-managed";
    protected final static String apiSastScanJsonManaged = "/api/sast/scan-json-managed";
    protected final static String apiSastState = "/api/sast/state?build-number={build-number}&start-pos={start-pos}";

    @Test
    @DisplayName("Upload sources zip to existing project")
    public void testExistingProjectUpload() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        File file = new File(getClass().getClassLoader().getResource("code/test.java.zip").getFile());
        body.add("file", new FileSystemResource(file));
        body.add("project", "DEVEL.JAVA");
        body.add("current", 0);
        body.add("total", 1);

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = integrationServerRestTemplate(clientIdNormal, loginTestUser);
        ResponseEntity<String> response = restTemplate.postForEntity(rootUrl + apiSastUpload, requestEntity, String.class);
    }

    protected Integer startExistingProjectScan(String projectName, String nodeName) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("project-name", projectName);
        body.add("node", nodeName);
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = integrationServerRestTemplate(clientIdNormal, loginTestUser);
        ResponseEntity<Integer> response = restTemplate.postForEntity(rootUrl + apiSastScanUiManaged, requestEntity, Integer.class);
        System.out.println("SAST job number is " + response.getBody());
        return response.getBody();
    }

    protected Integer startJsonManagedProjectScan(String projectName, String nodeName, String settings, String policy) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("project-name", projectName);
        body.add("node", nodeName);
        body.add("settings", settings);
        body.add("policy", policy);
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = integrationServerRestTemplate(clientIdNormal, loginTestUser);
        ResponseEntity<Integer> response = restTemplate.postForEntity(rootUrl + apiSastScanJsonManaged, requestEntity, Integer.class);
        System.out.println("SAST job number is " + response.getBody());
        return response.getBody();
    }

    protected void waitForSastJob(int buildId) throws Exception {
        RestTemplate restTemplate = integrationServerRestTemplate(clientIdNormal, loginTestUser);
        int pos = 0;
        do {
            JobState state = restTemplate.getForObject(rootUrl + apiSastState, JobState.class, buildId, pos);
            if (state.getPos() != pos)
                System.out.print(state.getLog());
            pos = state.getPos();
            if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
            Thread.sleep(1000);
        } while (true);
    }

    @Test
    @DisplayName("Start scan of existing project")
    public void testExistingProjectScan() throws Exception {
        startExistingProjectScan("DEVEL.JAVA", "PTAI");
    }

    @Test
    @DisplayName("Start scan of existing project and show console log")
    public void testExistingProjectScanState() throws Exception {
        Integer buildNumber = startExistingProjectScan("DEVEL.JAVA", "PTAI");
        waitForSastJob(buildNumber);
    }

    @Test
    @DisplayName("Start scan of existing JSON-defined project")
    public void testExistingProjectJsonScan() throws Exception {
        ClassLoader cl = getClass().getClassLoader();
        String settingsData = IOUtils.toString(
                cl.getResourceAsStream("json/settings/settings.0.json"),
                StandardCharsets.UTF_8.name());
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        ScanSettings settings = jsonMapper.readValue(settingsData, ScanSettings.class);


        String policy = IOUtils.toString(
                cl.getResourceAsStream("json/policy/policy.0.json"),
                StandardCharsets.UTF_8.name());

        Integer buildNumber = startJsonManagedProjectScan(settings.getProjectName(), "PTAI", settingsData, policy);
        waitForSastJob(buildNumber);
    }


}
