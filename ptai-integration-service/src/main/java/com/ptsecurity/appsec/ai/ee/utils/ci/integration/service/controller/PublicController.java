package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.ServiceUnavailableException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api/public")
public class PublicController {
    @Autowired
    BuildProperties buildProperties;

    @GetMapping("/about")
    public ResponseEntity<String> getAbout() throws ServiceUnavailableException {
        String res = "PT AI EE integration service";
        return new ResponseEntity<String>(res, HttpStatus.OK);
    }

    @GetMapping("/build-info")
    public ResponseEntity<BuildInfo> getBuildInfo() throws ServiceUnavailableException {
        DateTimeFormatter formatter = DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());

        return new ResponseEntity<BuildInfo>(
                new BuildInfo()
                        .date(formatter.format(buildProperties.getTime()))
                        .name(buildProperties.getName())
                        .version(buildProperties.getVersion()), HttpStatus.OK);
    }
}
