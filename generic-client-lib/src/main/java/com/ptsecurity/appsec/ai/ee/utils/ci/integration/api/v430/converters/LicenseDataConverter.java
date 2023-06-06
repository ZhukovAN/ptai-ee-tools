package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v430.converters;

import com.ptsecurity.appsec.ai.ee.LicenseData;
import com.ptsecurity.appsec.ai.ee.server.v430.api.model.ProgrammingLanguageGroup;
import com.ptsecurity.appsec.ai.ee.server.v430.api.model.EnterpriseLicenseModel;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

@Slf4j
public class LicenseDataConverter {
    public static final Map<ProgrammingLanguageGroup, String> LANGUAGES_MAP = new HashMap<>();

    static {
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.NONE, "None");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.PHP, "PHP");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.JAVA, "Java");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.CANDCPLUSPLUS, "C/C++");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.JAVASCRIPT, "JavaScript/TypeScript");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.SQL, "SQL");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.OBJECTIVEC, "Objective-C");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.SWIFT, "Swift");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.PYTHON, "Python");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.CSHARP, "C#");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.VB, "VB.NET");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.GO, "Go");
        LANGUAGES_MAP.put(ProgrammingLanguageGroup.KOTLIN, "Kotlin");
    }

    @NonNull
    public static LicenseData convert(@NonNull final EnterpriseLicenseModel licenseData) {
        final List<String> languages = new ArrayList<>();
        if (null == licenseData.getLanguages() || licenseData.getLanguages().isEmpty()) {
            log.warn("License languages list is empty");
            log.trace(licenseData.toString());
        } else
            licenseData.getLanguages().stream().map(LANGUAGES_MAP::get).filter(StringUtils::isNotEmpty).forEach(languages::add);
        return LicenseData.builder()
                .languages(languages)
                .startDate(null)
                .endDate(Objects.requireNonNull(licenseData.getEndDate(), "License end date is null"))
                .number(Objects.requireNonNull(licenseData.getLicenseNumber(), "License number is null"))
                .build();
    }
}
