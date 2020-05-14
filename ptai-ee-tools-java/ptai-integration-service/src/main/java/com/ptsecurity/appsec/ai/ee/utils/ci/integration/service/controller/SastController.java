package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.SastService;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import liquibase.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.multipart.MultipartFile;

import javax.naming.ServiceUnavailableException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/sast")
@Slf4j
public class SastController {
    @Autowired
    SastService sastService;

    @PostMapping(value = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> upload(
            @RequestParam String project,
            @RequestParam MultipartFile file,
            @RequestParam int current,
            @RequestParam int total,
            @RequestParam(required = false) String uploadId) {
        String res = sastService.upload(project, file, current, total, uploadId);
        return new ResponseEntity<String>(res, HttpStatus.OK);
    }

    @PostMapping(value = "/scan-ui-managed", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Integer> scanUiManaged(
            @RequestParam(name = "project-name") String project,
            @RequestParam(name = "node") String node) throws ServiceUnavailableException {
        Integer res = sastService.scanUiManaged(project, node)
                .orElseThrow(ServiceUnavailableException::new);
        return new ResponseEntity<Integer>(res, HttpStatus.OK);
    }

    @PostMapping(value = "/scan-json-managed", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Integer> scanJsonManaged(
            @RequestParam(name = "project-name") String project,
            @RequestParam(name = "node") String node,
            @RequestParam(name = "settings") String settingsJson,
            @RequestParam(name = "policy") String policyJson) throws ServiceUnavailableException, IOException {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        ScanSettings settings = jsonMapper.readValue(settingsJson, ScanSettings.class);
        // Workaround for missing site settings problem
        if (StringUtils.isEmpty(settings.getSite())) {
            settings.setSite("http://localhost:8080");
            log.warn("It is strictly recommended to set site address in scan settings");
        }
        Policy[] policy = null;
        if (StringUtils.isNotEmpty(policyJson))
            policy = jsonMapper.readValue(policyJson, Policy[].class);
        Integer res = sastService.scanJsonManaged(project, node, settings, policy).orElseThrow(ServiceUnavailableException::new);
        return new ResponseEntity<Integer>(res, HttpStatus.OK);
    }

    @GetMapping(value = "/state", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JobState> getJobState(
            @RequestParam(name = "scan-id") Integer scanId,
            @RequestParam(name = "start-pos") int startPos) throws ServiceUnavailableException {
        JobState res = sastService.getJobState(scanId, startPos)
                .orElseThrow(ServiceUnavailableException::new);
        return new ResponseEntity<JobState>(res, HttpStatus.OK);
    }

    @GetMapping(value = "/results", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<String>> getJobResults(@RequestParam(name = "scan-id") Integer scanId) throws ServiceUnavailableException {
        List<String> res = sastService.getJobResults(scanId)
                .orElseThrow(ServiceUnavailableException::new);
        return new ResponseEntity<List<String>>(res, HttpStatus.OK);
    }

    @GetMapping(value = "/result", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public void getJobResult(
            @RequestParam(name = "scan-id") Integer scanId,
            @RequestParam(name = "artifact") String artifact,
            HttpServletResponse response) throws ServiceUnavailableException {
        ReadableByteChannel res = sastService.getJobResult(scanId, artifact)
                .orElseThrow(ServiceUnavailableException::new);
        response.setContentType("application/octet-stream");
        try {
            ByteStreams.copy(res, Channels.newChannel(response.getOutputStream()));
        } catch (IOException e) {
            throw new ServiceUnavailableException();
        }
    }

    @PostMapping(value = "/stop")
    public ResponseEntity stop(@RequestParam(name = "scan-id") Integer scanId) {
        sastService.stopScan(scanId);
        return new ResponseEntity(HttpStatus.OK);
    }
}
