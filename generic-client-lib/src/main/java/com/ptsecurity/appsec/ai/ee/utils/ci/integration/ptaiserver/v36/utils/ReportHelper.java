package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils;

import lombok.NonNull;

import java.util.UUID;

public class ReportHelper {
    protected static final String DUPLICATE_INDEX_PLACEHOLDER = "." + UUID.randomUUID().toString();

    public static String removePlaceholder(@NonNull final String fileName) {
        return replacePlaceholder(fileName, "");
    }

    public static String replacePlaceholder(@NonNull final String fileName, @NonNull final String replacement) {
        return fileName.replaceAll(DUPLICATE_INDEX_PLACEHOLDER, replacement);
    }

    public static String generateReportFileNameTemplate(
            @NonNull final String template,
            @NonNull final String locale,
            @NonNull final String format) {
        // Resulting file name is to be Windows-compatible, so let's replace
        // some characters
        String name = template.replaceAll("[:\\\\/*?|<>]", "_");
        name = name.replaceAll("\"", "");
        name = name.replaceAll(" ", "-");
        // reportName += String.format(".%1$tY%1$tm%1$td%1$tH%1$tM%1$tS", new Date());
        name += String.format(".%s", locale.toLowerCase());
        // As there may be duplicates we need to create unique placeholder
        // that will be replaced by duplicate index or empty string (if there's exactly one report)
        name += DUPLICATE_INDEX_PLACEHOLDER;
        name += String.format(".%s", format.toLowerCase());
        return name;
    }
}
