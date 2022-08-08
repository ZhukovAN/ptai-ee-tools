package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.BaseCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.PasswordCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import picocli.CommandLine;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public abstract class BaseCommand {
    @AllArgsConstructor(access = AccessLevel.PACKAGE)
    public enum ExitCode {
        SUCCESS(Plugin.SUCCESS),
        FAILED(Plugin.FAILED),
        INVALID_INPUT(Plugin.INVALID_INPUT);

        @Getter
        @JsonProperty
        private final int code;
    }

    /**
     * This class defines set of output files to be generated after
     * AST complete. Class allows to generate reports using explicit
     * definition of templates, locales, file names etc. using CLI
     * parameters or define bunch of reports in JSON file. These
     * options are mutually exclusive, so corresponding class instance
     * must be annotated with @CommandLine.ArgGroup(exclusive = true)
     */
    public static class Reporting {
        /**
         * Reports to be generated are defined using JSON file and
         * no other reports are to be done
         */
        @CommandLine.Option(
                names = {"--report-json"}, order = 1,
                required = true,
                paramLabel = "<file>",
                description = "JSON file that defines reports to be generated")
        Path reportingJson = null;

        /**
         * Reports to be generated are directly defined in CLI parameters
         * as file names, template, locale, format etc.
         */
        @CommandLine.ArgGroup(exclusive = false)
        ExplicitReporting reporting = null;

        /**
         * Method converts CLI reporting parameters to {@link Reports} instance.
         * @return {@link Reports} instance that is made of CLI parameters
         * @throws GenericException EXception that contains error details if CLI-to-Reports conversion failed
         */
        public Reports convert() throws GenericException {
            if (null != reporting) {
                Reports reports = new Reports();
                // Convert CLI-defined report / export data to generic Reports instance
                if (null != reporting.report)
                    reports.getReport().add(Reports.Report.builder()
                            .fileName(reporting.report.file.normalize().toString())
                            .template(reporting.report.template)
                            .includeDfd(reporting.report.includeDfd)
                            .includeGlossary(reporting.report.includeGlossary)
                            .build());
                if (null != reporting.raw)
                    reports.getRaw().add(Reports.RawData.builder()
                            .fileName(reporting.raw.normalize().toString())
                            .build());
                if (null != reporting.sarif)
                    reports.getSarif().add(Reports.Sarif.builder()
                            .fileName(reporting.sarif.file.normalize().toString())
                            .build());
                if (null != reporting.sonarGiif)
                    reports.getSonarGiif().add(Reports.SonarGiif.builder()
                            .fileName(reporting.sonarGiif.file.normalize().toString())
                            .build());
                return reports;
            } else {
                // Load Reports instance from JSON file
                String json = call(
                        () -> FileUtils.readFileToString(reportingJson.toFile(), StandardCharsets.UTF_8),
                        Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_settings_message_invalid());
                return ReportUtils.validateJsonReports(json);
            }
        }

        public void addSubJobs(@NonNull final GenericAstJob owner) throws GenericException {
            Reports reports = convert();
            if (null == reports) return;
            for (com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report report : reports.getReport())
                com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Report.builder().owner(owner).report(report).build().attach(owner);
            for (Reports.RawData rawData : reports.getRaw())
                RawJson.builder().owner(owner).rawData(rawData).build().attach(owner);
        }
    }

    /**
     * Class defines AST reporting settings where all the report files
     * are defined explicitly i.e. if we need HTML/PDF report then we
     * define its format, template and locale using @report field
     */
    public static class ExplicitReporting {

        /**
         * Human-readable report definition that includes
         * format (html), template name, locale and
         * optional filters
         */
        @CommandLine.ArgGroup(exclusive = false)
        public Report report = null;

        /**
         * Machine-readable report that generated via
         * /api/Projects/{projectId}/scanResults/{scanResultId}/issues API call
         */
        @CommandLine.Option(
                names = { "--raw-data-file" }, order = 1,
                paramLabel = "<file>",
                description = "JSON file where raw issues data are to be saved")
        public Path raw = null;

        @CommandLine.ArgGroup(exclusive = false)
        public Sarif sarif = null;

        @CommandLine.ArgGroup(exclusive = false)
        public SonarGiif sonarGiif = null;
    }

    /**
     * Class defines group of CLI parameters to define single
     * generated report file. As those files are template-dependent,
     * we need to define template name, locale and format
     */
    @Getter @Setter
    @NoArgsConstructor
    public static class Report {
        @CommandLine.Option(
                names = {"--report-template"}, order = 1,
                required = true,
                paramLabel = "<template>",
                description = "Template name of report to be generated")
        public String template;

        /**
         * Generated report file name
         */
        @CommandLine.Option(
                names = { "--report-file" }, order = 4,
                required = true,
                paramLabel = "<file>",
                description = "File name where generated report is to be saved")
        public Path file;

        @CommandLine.Option(
                names = {"--report-include-dfd"}, order = 5,
                description = "Enable this option if you want to add the dataflow diagram to the report")
        protected boolean includeDfd = false;

        @CommandLine.Option(
                names = {"--report-include-glossary"}, order = 6,
                description = "Enable this option if you want to add reference information about vulnerabilities to the report")
        protected boolean includeGlossary = false;
    }

    @Getter @Setter
    @NoArgsConstructor
    public static class Sarif {
        /**
         * Generated report file name
         */
        @CommandLine.Option(
                names = { "--sarif-report-file" }, order = 4,
                required = true,
                paramLabel = "<file>",
                description = "File name where generated Static Analysis Results Interchange Format (SARIF) report is to be saved")
        public Path file;
    }

    @Getter @Setter
    @NoArgsConstructor
    public static class SonarGiif {
        /**
         * Generated report file name
         */
        @CommandLine.Option(
                names = { "--giif-report-file" }, order = 4,
                required = true,
                paramLabel = "<file>",
                description = "File name where generated SonarQube Generic Issue Import Format (GIIF) report is to be saved")
        public Path file;
    }

    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI server URL, i.e. https://ptai.domain.org:443")
    protected URL url;

    @Getter
    @Setter
    @NoArgsConstructor
    public static class Credentials {
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class LoginPassword {
            @CommandLine.Option(
                    names = {"--user"},
                    required = true, order = 2,
                    paramLabel = "<user>",
                    description = "PT AI user name")
            @Builder.Default
            protected String user = null;

            @CommandLine.Option(
                    names = {"--password"},
                    required = true, order = 3,
                    paramLabel = "<password>",
                    description = "PT AI user password")
            @Builder.Default
            protected String password = null;
        }

        @CommandLine.ArgGroup(exclusive = false)
        protected LoginPassword loginPassword = null;

        @CommandLine.Option(
                names = {"-t", "--token"},
                required = true, order = 2,
                paramLabel = "<token>",
                description = "PT AI server API token")
        protected String token = null;

        public Credentials(@NonNull final BaseCredentials credentials) {
            if (credentials instanceof TokenCredentials) {
                TokenCredentials tokenCredentials = (TokenCredentials) credentials;
                token = tokenCredentials.getToken();
            } else {
                PasswordCredentials passwordCredentials = (PasswordCredentials) credentials;
                loginPassword = LoginPassword.builder()
                        .user(passwordCredentials.getUser())
                        .password(passwordCredentials.getPassword())
                        .build();
            }
        }

        public BaseCredentials getBaseCredentials() {
            return null == getToken()
                    ? PasswordCredentials.builder().user(getLoginPassword().getUser()).password(getLoginPassword().getPassword()).build()
                    : TokenCredentials.builder().token(getToken()).build();
        }
    }

    @CommandLine.ArgGroup()
    protected Credentials credentials = null;

    @CommandLine.Option(
            names = {"--truststore"}, order = 3,
            paramLabel = "<path>",
            description = "Path to PEM file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 4,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @CommandLine.Option(
            names = {"--insecure"}, order = 99,
            description = "Do not verify CA certificate chain")
    protected boolean insecure = false;
}
