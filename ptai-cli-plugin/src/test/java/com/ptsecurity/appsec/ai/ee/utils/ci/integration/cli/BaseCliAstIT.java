package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;

import java.nio.file.Files;
import java.nio.file.Path;

public abstract class BaseCliAstIT extends BaseCliIT {
    protected Path destination;

    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");
    }
}
