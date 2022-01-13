package com.ptsecurity.appsec.ai.ee.server.integration.rest.test;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public abstract class BaseIT extends BaseTest {
    public static final String TOKEN = (null != System.getenv("ptai.token"))
            ? System.getenv("ptai.token")
            : "3F4y+YC+ZSkwkAGvzVDLvzvH4QXO+E2m";

    public static final String USER = (null != System.getenv("ptai.user"))
            ? System.getenv("ptai.user")
            : "Administrator";

    public static final String PASSWORD = (null != System.getenv("ptai.password"))
            ? System.getenv("ptai.password")
            : "P@ssw0rd";

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
