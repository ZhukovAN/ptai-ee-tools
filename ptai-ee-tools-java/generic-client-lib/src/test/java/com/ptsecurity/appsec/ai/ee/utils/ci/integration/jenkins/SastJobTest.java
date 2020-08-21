package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.ComputerSet;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.HudsonMasterComputer;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SastJobTest {
    private final static String ip = "127.0.0.1";
    @Test
    void execute() {
        SastJob sast = new SastJob();
        sast.setVerbose(true);
        sast.setConsoleLog(System.out);
        sast.setJobName("SAST/UI-managed SAST pipeline");
        sast.setUrl("http://" + ip + ":38080/jenkins");
        sast.setUserName("svc_ptai");
        sast.setToken("114b330974dba8827019a5988ed461f8af");
        sast.setProjectName("JUnit.01");
        sast.setNodeName("PTAI");
        try {
            sast.init();
            Integer res = sast.execute(Files.createTempDirectory("PT_").toString());
            PtaiResultStatus status = PtaiResultStatus.convert(res);
        } catch (JenkinsClientException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void executeSsl() {
        try {
            SastJob sast = new SastJob();
            sast.setVerbose(true);
            sast.setConsoleLog(System.out);
            sast.setJobName("SAST/UI-managed SAST pipeline");
            sast.setUrl("https://" + ip + ":38443/jenkins");
            // sast.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ca.chain.pem.crt"))));
            sast.setTrustStoreFile("src\\test\\resources\\keys\\trust.p12");
            sast.setTrustStoreType("PKCS12");

            sast.setUserName("svc_ptai");
            sast.setPassword("P@ssw0rd");

            sast.setProjectName("JUnit.01");
            sast.setNodeName("LOCAL");

            sast.init();
            Integer res = sast.execute(Files.createTempDirectory("PT_").toString());
            PtaiResultStatus status = PtaiResultStatus.convert(res);
        } catch (JenkinsClientException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testQueueIdRegex() {
        Map<String, List<String>> headers = new HashMap<>();
        String location = "https://ci.domain.org/queue/item/308/";
        headers.put("Location", Arrays.asList(location));
        ApiResponse<Void> response = new ApiResponse<>(200, headers);
        Integer id = Client.getQueueId(response);
        System.out.println(String.format("%d", id));
        assertEquals(308, id);
        location = "https://www.github.com";
        headers.replace("Location", Arrays.asList(location));
        response = new ApiResponse<>(200, headers);
        id = Client.getQueueId(response);
        assertEquals(null, id);
    }

    @SneakyThrows
    @Test
    public void testNodeList() {
        Client jenkins = new Client();
        jenkins.setVerbose(true);
        jenkins.setConsoleLog(System.out);
        jenkins.setUrl("http://jenkins.domain.org");
        jenkins.setUserName("svc_ptai");
        jenkins.setPassword("P@ssw0rd");

        jenkins.init();
        ComputerSet nodes = jenkins.jenkinsApi.getComputer(0);
        nodes.getComputer().stream()
                .map(n -> n.getAssignedLabels())
                .flatMap(l -> l.stream())
                .filter(l -> l.getName().equals("PTAI"))
                .forEach(l -> System.out.println(l.getName()));
        for (HudsonMasterComputer node : nodes.getComputer())
            System.out.println(node.getDisplayName());
    }
}