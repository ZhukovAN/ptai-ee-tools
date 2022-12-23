package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils.GracefulShutdown;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.FileSaver;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
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
public abstract class GenericCliAstJob extends GenericAstJob implements FileSaver, TextOutput {
    protected Path input;
    protected String includes;
    protected String excludes;
    protected boolean useDefaultExcludes;
    protected Path output;

    protected Path truststore;
    private GracefulShutdown shutdown;

    @Override
    protected void init() throws GenericException {
        String caCertsPem = (null == truststore)
                ? null
                : call(
                    () -> {
                        log.debug("Loading trusted certificates from {}", truststore.toString());
                        return new String(Files.readAllBytes(truststore), UTF_8);
                    },
                    Resources.i18n_ast_settings_server_ca_pem_message_file_read_failed());
        connectionSettings.setCaCertsPem(caCertsPem);

        fileOps = LocalFileOperations.builder()
                .saver(this)
                .console(this)
                .build();
        astOps = LocalAstOperations.builder()
                .owner(this)
                .build();
    }
}
