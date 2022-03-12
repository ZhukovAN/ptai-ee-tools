package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public abstract class BaseCliIT extends BaseClientIT {
    protected Path PEM;
    protected Path DUMMY;

    @SneakyThrows
    @BeforeEach
    public void pre() {
        PEM = Files.createTempFile(TEMP_FOLDER, "ptai-", "-ca");
        FileUtils.write(PEM.toFile(), BaseIT.CA, StandardCharsets.UTF_8);
        DUMMY = Files.createTempFile(TEMP_FOLDER, "ptai-", "-ca");
        FileUtils.write(DUMMY.toFile(), BaseIT.DUMMY, StandardCharsets.UTF_8);
    }
}
