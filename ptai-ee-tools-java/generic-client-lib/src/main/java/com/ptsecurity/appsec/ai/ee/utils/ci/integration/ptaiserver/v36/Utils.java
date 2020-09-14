package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectLight;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ProgrammingLanguageHelper;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ProgrammingLanguageHelper.LANGUAGES;

@Log
public class Utils extends BaseClient {
    public EnterpriseLicenseData getLicenseData() throws ApiException {
        return callApi(() -> licenseApi.apiLicenseGet(), "PT AI license information retrieve failed");
    }

    public static String getLicenseDataBanner(@NonNull final EnterpriseLicenseData licenseData) throws ApiException {
        final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        StringBuilder builder = new StringBuilder();
        builder
                .append("start date: ")
                .append(formatter.format(licenseData.getStartDate()))
                .append(", expiration date: ")
                .append(formatter.format(licenseData.getEndDate()))
                .append(", projects: ")
                .append(licenseData.getLimitProjects());
        if (0 != licenseData.getLanguages().size()) {
            builder.append(", languages: ");
            List<String> languageNames = licenseData.getLanguages().stream()
                    .map(l -> LANGUAGES.getOrDefault(l, ""))
                    .filter(l -> StringUtils.isNotEmpty(l))
                    .sorted().collect(Collectors.toList());
            String[] languageNamesArray = new String[languageNames.size()];
            languageNamesArray = languageNames.toArray(languageNamesArray);
            builder.append(String.join(", ", languageNamesArray));
        }
        return builder.toString();
    }

    public boolean healthCheck() throws ApiException {
        HealthCheck health = callApi(() -> healthCheckApi.healthSummaryGet(), "PT AI health check failed");

        return null != health;
    }
}
