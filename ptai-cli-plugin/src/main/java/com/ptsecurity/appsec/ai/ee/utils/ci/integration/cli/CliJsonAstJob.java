package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@Getter
@Setter
@SuperBuilder
public class CliJsonAstJob extends GenericCliAstJob {
    protected Path settings;
    protected Path policy;

    @Override
    protected void init() throws GenericException {
        String jsonSettings = (null == settings)
                ? null
                : call(() -> {
                    log.debug("Loading JSON-defined scan settings from {}", settings);
                    return new String(Files.readAllBytes(settings), UTF_8);
        }, "JSON settings file read failed");

        String jsonPolicy = (null == policy)
                ? null
                : call(() -> {
            log.debug("Loading JSON-defined AST policy from {}", policy);
            return new String(Files.readAllBytes(policy), UTF_8);
        }, "JSON policy file read failed");

        super.init();
        this.setupOps = JsonAstJobSetupOperationsImpl.builder()
                .jsonSettings(jsonSettings)
                .jsonPolicy(jsonPolicy)
                .owner(this)
                .build();
    }
}
