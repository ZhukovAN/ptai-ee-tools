package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.ptsecurity.appsec.ai.ee.LicenseData;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ProgrammingLanguage;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

@Slf4j
public class LicenseDataConverter {
    public static final Map<ProgrammingLanguage, String> LANGUAGES_MAP = new HashMap<>();

    static {
        LANGUAGES_MAP.put(ProgrammingLanguage.None, "None");
        LANGUAGES_MAP.put(ProgrammingLanguage.DotNet, ".NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.Php, "PHP");
        LANGUAGES_MAP.put(ProgrammingLanguage.Java, "Java");
        LANGUAGES_MAP.put(ProgrammingLanguage.Html, "HTML");
        LANGUAGES_MAP.put(ProgrammingLanguage.JavaScript, "JavaScript");
        LANGUAGES_MAP.put(ProgrammingLanguage.All, "All");
        LANGUAGES_MAP.put(ProgrammingLanguage.SandBox, "SandBox");
        LANGUAGES_MAP.put(ProgrammingLanguage.Binary, "Binary");
        LANGUAGES_MAP.put(ProgrammingLanguage.PlSql, "PL/SQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.TSql, "T-SQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.MySql, "MySQL");
        LANGUAGES_MAP.put(ProgrammingLanguage.Aspx, "ASP.NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.C, "C");
        LANGUAGES_MAP.put(ProgrammingLanguage.CPlusPlus, "C++");
        LANGUAGES_MAP.put(ProgrammingLanguage.ObjectiveC, "ObjectiveC");
        LANGUAGES_MAP.put(ProgrammingLanguage.Swift, "Swift");
        LANGUAGES_MAP.put(ProgrammingLanguage.Python, "Python");
        LANGUAGES_MAP.put(ProgrammingLanguage.CSharp, "C#");
        LANGUAGES_MAP.put(ProgrammingLanguage.VB, "VB.NET");
        LANGUAGES_MAP.put(ProgrammingLanguage.Go, "Go");
        LANGUAGES_MAP.put(ProgrammingLanguage.Kotlin, "Kotlin");
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
                .startDate(Objects.requireNonNull(licenseData.getStartDate(), "License start date is null"))
                .endDate(Objects.requireNonNull(licenseData.getEndDate(), "License end date is null"))
                .number(Objects.requireNonNull(licenseData.getLicenseNumber(), "License number is null"))
                .build();
    }
}
