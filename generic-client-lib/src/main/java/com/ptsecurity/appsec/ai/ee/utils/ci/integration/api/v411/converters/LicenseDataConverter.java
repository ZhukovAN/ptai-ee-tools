package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters;

import com.ptsecurity.appsec.ai.ee.LicenseData;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ProgrammingLanguage;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

@Slf4j
public class LicenseDataConverter {
    public static final Map<ProgrammingLanguage, String> LANGUAGES_MAP = new HashMap<>();

    static {
        LANGUAGES_MAP.put(ProgrammingLanguage.NONE, "None");
        LANGUAGES_MAP.put(ProgrammingLanguage.DOTNET, ".NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.PHP, "PHP");
        LANGUAGES_MAP.put(ProgrammingLanguage.JAVA, "Java");
        LANGUAGES_MAP.put(ProgrammingLanguage.HTML, "HTML");
        LANGUAGES_MAP.put(ProgrammingLanguage.JAVASCRIPT, "JavaScript");
        LANGUAGES_MAP.put(ProgrammingLanguage.ALL, "All");
        LANGUAGES_MAP.put(ProgrammingLanguage.SANDBOX, "SandBox");
        LANGUAGES_MAP.put(ProgrammingLanguage.BINARY, "Binary");
        LANGUAGES_MAP.put(ProgrammingLanguage.PLSQL, "PL/SQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.TSQL, "T-SQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.MYSQL, "MySQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.ASPX, "ASP.NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.C, "C");
        LANGUAGES_MAP.put(ProgrammingLanguage.CPLUSPLUS, "C++");
        LANGUAGES_MAP.put(ProgrammingLanguage.OBJECTIVEC, "ObjectiveC");
        LANGUAGES_MAP.put(ProgrammingLanguage.SWIFT, "Swift");
        LANGUAGES_MAP.put(ProgrammingLanguage.PYTHON, "Python");
        LANGUAGES_MAP.put(ProgrammingLanguage.CSHARP, "C#");
        LANGUAGES_MAP.put(ProgrammingLanguage.VB, "VB.NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.GO, "Go");
        LANGUAGES_MAP.put(ProgrammingLanguage.KOTLIN, "Kotlin");
    }

    @NonNull
    public static LicenseData convert(@NonNull final EnterpriseLicenseData licenseData) {
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
