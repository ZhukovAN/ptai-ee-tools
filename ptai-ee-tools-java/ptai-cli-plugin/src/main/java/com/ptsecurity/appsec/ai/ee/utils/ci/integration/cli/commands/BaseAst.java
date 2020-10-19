package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import picocli.CommandLine;

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
        @CommandLine.Option(
                names = {"--report-template"}, order = 1,
                required = true,
                paramLabel = "<template>",
                description = "Template name of report to be generated")
        public String template = null;

        @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
        public enum Format {
            HTML("Html"),
            XML("Xml"),
            JSON("Json"),
            PDF("Pdf");

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
}
