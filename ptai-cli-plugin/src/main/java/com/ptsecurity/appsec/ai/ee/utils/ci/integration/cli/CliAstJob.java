package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.charset.StandardCharsets.UTF_8;

@Getter
@Setter
@SuperBuilder
public class CliAstJob extends AstJob {
    protected Path input;
    protected String includes;
    protected String excludes;
    protected Path output;

    protected BaseCommand.Reporting reporting;
    protected Path truststore;
    protected Path settings;
    protected Path policy;

    @Override
    public boolean unsafeInit() throws ApiException {
        jsonSettings = (null == settings)
                ? null
                : Base.callApi(() -> new String(Files.readAllBytes(settings), UTF_8), "JSON settings file read failed");
        if (null != jsonSettings)
            name = JsonSettingsHelper.verify(jsonSettings).getProjectName();

        jsonPolicy = (null == policy)
                ? null
                : Base.callApi(() -> new String(Files.readAllBytes(policy), UTF_8), "JSON policy file read failed");

        caCertsPem = (null == truststore)
                ? null
                : callApi(
                () -> new String(Files.readAllBytes(truststore), UTF_8),
                Resources.i18n_ast_settings_server_ca_pem_message_file_read_failed());
        reports = (null == reporting) ? null : reporting.convert();

        astOps = LocalAstOperations.builder()
                .owner(this)
                .build();
        fileOps = LocalFileOperations.builder()
                .owner(this)
                .build();

        return super.unsafeInit();
    }
}
