package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.Node;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.DiagnosticService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.ServiceUnavailableException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/diagnostic")
public class DiagnosticController {
    @Autowired
    DiagnosticService diagnosticService;

    @GetMapping(value = "/check", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ComponentsStatus> getComponentsStatus() throws ServiceUnavailableException {
        ComponentsStatus res = diagnosticService.getComponentsStatus();
        return new ResponseEntity<ComponentsStatus>(res, HttpStatus.OK);
    }

    @GetMapping(value = "/project", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UUID> getProject(@RequestParam(name = "name") String name) throws ServiceUnavailableException {
        UUID projectId = diagnosticService.getProjectByName(name);
        if (null == projectId)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<UUID>(projectId, HttpStatus.OK);
    }

    @GetMapping(value = "/nodes", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Node>> getAstNodes() throws ServiceUnavailableException {
        List<Node> res = diagnosticService.getAstNodes();
        if (null == res)
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        else
            return new ResponseEntity<List<Node>>(res, HttpStatus.OK);
    }
}
