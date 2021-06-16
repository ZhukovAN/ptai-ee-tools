package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.api.LicenseApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.systemmanagement.api.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.systemmanagement.model.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ProgrammingLanguageHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@DisplayName("Lightweight PT AI API integration tests")
@Tag("integration")
public class LightweightIT extends BaseIT {
    @DisplayName("Test license data retrieval")
    @SneakyThrows
    @Test
    public void testLicenseData() {
        LicenseApi licenseApi = client.getLicenseApi();
        EnterpriseLicenseData licenseData = licenseApi.apiLicenseGet();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        StringBuilder builder = new StringBuilder();
        builder
                .append("Start date: ")
                .append(formatter.format(licenseData.getStartDate()))
                .append(", expiration date: ")
                .append(formatter.format(licenseData.getEndDate()))
                .append(", projects: ")
                .append(licenseData.getLimitProjects());
        if (0 != licenseData.getLanguages().size()) {
            builder.append(", LANGUAGES: ");
            List<String> languageNames = licenseData.getLanguages().stream()
                    .map(l -> ProgrammingLanguageHelper.LANGUAGES.getOrDefault(l, ""))
                    .filter(StringUtils::isNotEmpty)
                    .sorted().collect(Collectors.toList());
            String[] languageNamesArray = new String[languageNames.size()];
            languageNamesArray = languageNames.toArray(languageNamesArray);
            builder.append(String.join(", ", languageNamesArray));
        }
        System.out.println(builder.toString());
    }

    @DisplayName("Check JWT expiration dates")
    @SneakyThrows
    @Test
    public void testJwt() {
        JwtResponse jwtResponse = client.authenticate();

        // Let's extract data from jwt. As we have no signing key we need to strip signature from jwt
        String jwt = jwtResponse.getAccessToken().substring(0, jwtResponse.getAccessToken().lastIndexOf('.') + 1);
        Jwt<Header, Claims> untrusted = Jwts.parser()
                .setAllowedClockSkewSeconds(300)
                .parseClaimsJwt(jwt);
        Date expiration = untrusted.getBody().getExpiration();

        Thread.sleep(1000);

        jwtResponse = client.authenticate();
        jwt = jwtResponse.getAccessToken().substring(0, jwtResponse.getAccessToken().lastIndexOf('.') + 1);
        untrusted = Jwts.parser()
                .setAllowedClockSkewSeconds(300)
                .parseClaimsJwt(jwt);
        Assertions.assertTrue(untrusted.getBody().getExpiration().after(expiration));
    }

    @DisplayName("Test health check API")
    @SneakyThrows
    @Test
    public void testHealthCheck() {
        HealthCheckApi healthCheckApi = client.getHealthCheckApi();
        HealthCheck summary = healthCheckApi.healthSummaryGet();
        Assertions.assertFalse(summary.getServices().isEmpty());
    }
}
