package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings.ProgrammingLanguage.JAVA;
import static org.joor.Reflect.on;

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
