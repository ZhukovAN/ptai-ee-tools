package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;

import java.nio.file.Files;
import java.nio.file.Path;

public abstract class BaseCliAstIT extends BaseCliIT {
    protected Path sourcesPhpMedium;
    protected Path sourcesPhpHigh;
    protected Path sourcesJavaMisc;
    protected Path destination;

    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        sourcesPhpMedium = getPackedResourceFile("code/php-smoke-medium.7z");
        sourcesPhpHigh = getPackedResourceFile("code/php-smoke-high.7z");
        sourcesJavaMisc = getPackedResourceFile("code/java-app01.7z");
        destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");
    }
}
