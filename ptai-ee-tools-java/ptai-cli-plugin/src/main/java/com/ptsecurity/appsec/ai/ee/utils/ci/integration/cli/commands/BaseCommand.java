package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.StringHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ReportHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.java.Log;
import org.apache.commons.io.FileUtils;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Log
public abstract class BaseCommand {
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class ExitCode {
        @Getter
        protected int code;

        public static final ExitCode SUCCESS = new ExitCode(0);
        public static final ExitCode FAILED = new ExitCode(1);
        public static final ExitCode WARNINGS = new ExitCode(2);
        public static final ExitCode ERROR = new ExitCode(3);
        public static final ExitCode INVALID_INPUT = new ExitCode(1000);
    }

    public static class Report {
        @CommandLine.ArgGroup(exclusive = false)
        public ReportDefinition reportDefinition;

        @CommandLine.Option(
                names = {"--report-json"}, order = 1,
                required = true,
                paramLabel = "<file>",
                description = "JSON file that defines reports to be generated")
        public Path reportJson = null;

        public List<NamedReportDefinition> validate(@NonNull final Utils utils) throws ApiException {
            final List<NamedReportDefinition> reportDefinitions = new ArrayList<>();
            if (null != reportDefinition) {
                String reportName = ReportHelper.generateReportFileNameTemplate(
                        reportDefinition.template, reportDefinition.locale.getValue(), reportDefinition.format.getValue());
                reportName = ReportHelper.removePlaceholder(reportName);
                reportDefinitions.add(NamedReportDefinition.builder()
                        .name(reportName)
                        .template(reportDefinition.template)
                        .locale(reportDefinition.locale)
                        .format(reportDefinition.format)
                        .build());
            } else if (null != reportJson) {
                try {
                    String jsonStr = FileUtils.readFileToString(reportJson.toFile(), StandardCharsets.UTF_8);
                    NamedReportDefinition[] reportDefinitionsFromJson = BaseCommand.NamedReportDefinition.load(jsonStr);
                    reportDefinitions.addAll(Arrays.asList(reportDefinitionsFromJson));
                } catch (IOException e) {
                    throw ApiException.raise("File " + reportJson.toString() + " read failed", e);
                }
            }
            // Check if all the reports are exist
            List<String> missingReports = new ArrayList<>();
            reportDefinitions.stream().map(r -> r.locale).distinct().forEach(l -> {
                List<String> templates = utils.getReportTemplates(l.getValue()).stream()
                        .map(ReportTemplateModel::getName)
                        .collect(Collectors.toList());
                reportDefinitions.stream()
                        .filter(r -> l.equals(r.getLocale()))
                        .map(ReportDefinition::getTemplate)
                        .forEach(t -> {
                            if (!templates.contains(t)) missingReports.add(t + " [" + l + "]");
                        });
            });
            if (!missingReports.isEmpty())
                throw ApiException.raise(
                        "Not all report templates are exist on server",
                        new IllegalArgumentException("Missing reports are " + StringHelper.joinListGrammatically(missingReports)));
            return reportDefinitions;
        }
    }

    @Getter @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class ReportDefinition {
        @CommandLine.Option(
                names = {"--report-template"}, order = 1,
                required = true,
                paramLabel = "<template>",
                description = "Template name of report to be generated")
        public String template;

        @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
        public enum Format {
            HTML(ReportFormatType.HTML.getValue()),
            XML(ReportFormatType.XML.getValue()),
            JSON(ReportFormatType.JSON.getValue()),
            PDF(ReportFormatType.PDF.getValue());

            @Getter
            private final String value;
        }

        @CommandLine.Option(
                names = {"--report-format", "-f"}, order = 2,
                required = true,
                paramLabel = "<format>",
                description = "Format type of report to be generated, one of: HTML, XML, JSON, PDF")
        public Format format;

        @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
        public enum Locale {
            EN("en-US"), RU("ru-RU");

            @Getter
            private final String value;
        }

        @CommandLine.Option(
                names = {"--report-locale", "-l"}, order = 3,
                required = true,
                paramLabel = "<locale>",
                description = "Locale ID of report to be generated, one of EN, RU")
        public Locale locale;
    }

    @Getter @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class NamedReportDefinition extends ReportDefinition {
        @NonNull
        public String name;

        public static NamedReportDefinition[] load(String json) throws ApiException {
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
                return mapper.readValue(json, NamedReportDefinition[].class);
            } catch (Exception e) {
                throw ApiException.raise("JSON settings parse failed", e);
            }
        }
    }
}
