package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
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
    public ResponseEntity<UUID> getProject(@RequestParam(name = "projectName") String projectName) throws ServiceUnavailableException {
        UUID projectId = diagnosticService.getProjectByName(projectName);
        if (null == projectId)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        else
            return new ResponseEntity<UUID>(projectId, HttpStatus.OK);
    }
}
