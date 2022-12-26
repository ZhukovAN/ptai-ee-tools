package com.ptsecurity.appsec.ai.ee.server.integration.rest;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.Retention;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

@ExtendWith(EnvironmentExecutionCondition.class)
@Retention(RUNTIME)
public @interface Environment {
    ScanBrief.ApiVersion[] enabledFor();
}