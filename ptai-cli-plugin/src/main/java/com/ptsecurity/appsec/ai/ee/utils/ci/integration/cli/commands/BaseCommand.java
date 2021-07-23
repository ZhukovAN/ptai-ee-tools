package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.*;
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
        protected int code;
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
                if (null != reporting.data) {
                    Reports.Data data = new Reports.Data();
                    data.setFileName(reporting.data.file.normalize().toString());
                    data.setFormat(reporting.data.format);
                    data.setLocale(reporting.data.locale);
                    reports.getData().add(data);
                }
                if (null != reporting.report) {
                    Reports.Report report = new Reports.Report();
                    report.setFileName(reporting.report.file.normalize().toString());
                    report.setFormat(reporting.report.format);
                    report.setLocale(reporting.report.locale);
                    report.setTemplate(reporting.report.template);
                    reports.getReport().add(report);
                }
                if (null != reporting.raw) {
                    Reports.RawData raw = new Reports.RawData();
                    raw.setFileName(reporting.raw.normalize().toString());
                    reports.getRaw().add(raw);
                }
                return reports;
            } else {
                // Load Reports instance from JSON file
                String json = call(
                        () -> FileUtils.readFileToString(reportingJson.toFile(), StandardCharsets.UTF_8),
                        Resources.i18n_ast_result_reporting_json_message_file_read_failed());
                return Reports.validateJsonReports(json);
            }
        }
    }

    /**
     * Class defines AST reporting settings where all the report files
     * are defined explicitly i.e. if we need HTML/PDF report then we
     * define its format, template and locale using @report field
     */
    public static class ExplicitReporting {
        /**
         * Machine-readable data export file definition that
         * includes format (XML or JSON), locate and optional filters
         */
        @CommandLine.ArgGroup(exclusive = false)
        Data data = null;

        /**
         * Human-readable report definition that includes
         * format (html or PDF), template name, locale and
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
        Path raw = null;
    }

    /**
     * Class defines group of CLI parameters to define single exported
     * data file. As those files aren't template-dependent, we need
     * to define only locale and format
     */
    @Getter @Setter
    @NoArgsConstructor
    public static class Data {
        /**
         * Exported data file format. PT AI allows data export using XML and JSON formats
         */
        @CommandLine.Option(
                names = { "--data-format" }, order = 2,
                required = true,
                paramLabel = "<format>",
                description = "Format type of data to be exported, one of: ${COMPLETION-CANDIDATES}")
        public Reports.Data.Format format;

        /**
         * Exported data locale. PT AI allows data export using EN and RU locales
         */
        @CommandLine.Option(
                names = { "--data-locale" }, order = 3,
                required = true,
                paramLabel = "<locale>",
                description = "Locale ID of data to be exported, one of ${COMPLETION-CANDIDATES}")
        public Reports.Locale locale;

        /**
         * Generated report file name
         */
        @CommandLine.Option(
                names = { "--data-file" }, order = 4,
                required = true,
                paramLabel = "<file>",
                description = "File name where exported data is to be saved")
        public Path file;
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
         * Exported report file format. PT AI allows report generation using PDF and HTML formats
         */
        @CommandLine.Option(
                names = { "--report-format" }, order = 2,
                required = true,
                paramLabel = "<format>",
                description = "Format type of report to be generated, one of: ${COMPLETION-CANDIDATES}")
        public Reports.Report.Format format;

        /**
         * Generated report locale. PT AI allows report generation using EN and RU locales
         */
        @CommandLine.Option(
                names = { "--report-locale" }, order = 3,
                required = true,
                paramLabel = "<locale>",
                description = "Locale ID of report to be generated, one of ${COMPLETION-CANDIDATES}")
        public Reports.Locale locale;

        /**
         * Generated report file name
         */
        @CommandLine.Option(
                names = { "--report-file" }, order = 4,
                required = true,
                paramLabel = "<file>",
                description = "File name where generated report is to be saved")
        public Path file;
    }

    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI server URL, i.e. https://ptai.domain.org:443")
    protected URL url;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 2,
            paramLabel = "<token>",
            description = "PT AI server API token")
    protected String token = null;

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
