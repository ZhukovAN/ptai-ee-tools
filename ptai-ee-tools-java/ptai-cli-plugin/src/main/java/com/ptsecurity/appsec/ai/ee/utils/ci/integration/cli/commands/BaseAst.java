package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.java.Log;
import picocli.CommandLine;

import java.nio.file.Path;

@Log
public abstract class BaseAst {
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
        public String template = null;

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
        public Format format = null;

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
        public Locale locale = null;
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
                NamedReportDefinition[] res = mapper.readValue(json, NamedReportDefinition[].class);
                return res;
            } catch (Exception e) {
                throw ApiException.raise("JSON settings parse failed", e);
            }
        }
    }
}
