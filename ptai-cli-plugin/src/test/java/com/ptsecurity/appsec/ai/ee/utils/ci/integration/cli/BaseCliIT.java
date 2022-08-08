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
    /**
     * As CLI plugin accepts file-based truststores, we need
     * to save certificates from resources to PEM files
     */
    protected Path CA_PEM_FILE;

    protected Path DUMMY_CA_PEM_FILE;

    @SneakyThrows
    @BeforeEach
    public void pre() {
        CA_PEM_FILE = Files.createTempFile(TEMP_FOLDER(), "ptai-", "-ca-pem");
        FileUtils.write(CA_PEM_FILE.toFile(), CONNECTION().getCaPem(), StandardCharsets.UTF_8);
        DUMMY_CA_PEM_FILE = Files.createTempFile(TEMP_FOLDER(), "ptai-", "-dummy-ca-pem");
        FileUtils.write(DUMMY_CA_PEM_FILE.toFile(), BaseIT.DUMMY_CA_PEM, StandardCharsets.UTF_8);
    }
}
