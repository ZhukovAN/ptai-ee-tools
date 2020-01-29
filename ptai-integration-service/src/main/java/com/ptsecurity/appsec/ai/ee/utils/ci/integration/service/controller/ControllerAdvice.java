package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Optional;

@RestControllerAdvice
@Slf4j
public class ControllerAdvice {
    @ExceptionHandler(value = {JenkinsServerException.class})
    public ResponseEntity jenkinsServerException(JenkinsServerException ex, WebRequest request) {
        log.error(ex.getMessage());
        log.trace("Exception details", ex);
        Exception inner = ex.getInner();
        if (null != inner) {
            log.trace("Inner exception", inner);
            String data = JenkinsServerException.getInnerExceptionData(inner);
            if (StringUtils.isNotEmpty(data))
                log.trace("Inner exception data: {}", data);
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }
}
