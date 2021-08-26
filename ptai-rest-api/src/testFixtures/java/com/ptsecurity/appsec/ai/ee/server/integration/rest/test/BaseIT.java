package com.ptsecurity.appsec.ai.ee.server.integration.rest.test;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public class BaseIT extends BaseTest {
    public static final String EXISTING_PHP_SMOKE_MISC_PROJECT = "junit-it-php-smoke-misc";
    public static final String EXISTING_PHP_SMOKE_MEDIUM_PROJECT = "junit-it-php-smoke-medium";
    public static final String EXISTING_PHP_SMOKE_HIGH_PROJECT = "junit-it-php-smoke-high";

    public static final String TOKEN = (null != System.getenv("ptai.token"))
            ? System.getenv("ptai.token")
            : "6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5";
    public static final String URL = (null != System.getenv("ptai.url"))
            ? System.getenv("ptai.url")
            : "https://ptai.domain.org:443/";
    public static final String CA = CA();

    @SneakyThrows
    protected static String CA() {
        if (null != System.getenv("ptai.url"))
            return IOUtils.toString(new FileInputStream(System.getenv("ptai.ca.file")), StandardCharsets.UTF_8);
        return getResourceString("keys/domain.org.pem");
    }
}
