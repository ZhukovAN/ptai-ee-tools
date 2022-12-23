package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.misc.tools.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;

public abstract class BaseCliIT extends BaseClientIT {
    /**
     * As CLI plugin accepts file-based truststores, we need
     * to save certificates from resources to PEM files
     */
    protected Path CA_PEM_FILE;

    protected Path DUMMY_CA_PEM_FILE;

    @SneakyThrows
    @BeforeEach
    public void pre(@NonNull final TestInfo testInfo) {
        super.pre(testInfo);
        CA_PEM_FILE = TempFile.createFile().toPath();
        FileUtils.write(CA_PEM_FILE.toFile(), CONNECTION().getCaPem(), StandardCharsets.UTF_8);
        DUMMY_CA_PEM_FILE = TempFile.createFile().toPath();
        FileUtils.write(DUMMY_CA_PEM_FILE.toFile(), BaseIT.DUMMY_CA_PEM, StandardCharsets.UTF_8);
    }
}
