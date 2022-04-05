package com.ptsecurity.appsec.ai.ee.server.integration.rest.test;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public abstract class BaseIT extends BaseTest {
    public static final String TOKEN = (null != System.getenv("ptai.token"))
            ? System.getenv("ptai.token")
            : CONNECTION().getToken();

    public static final String USER = (null != System.getenv("ptai.user"))
            ? System.getenv("ptai.user")
            : CONNECTION().getUser();

    public static final String PASSWORD = (null != System.getenv("ptai.password"))
            ? System.getenv("ptai.password")
            : CONNECTION().getPassword();

    public static final String URL = (null != System.getenv("ptai.url"))
            ? System.getenv("ptai.url")
            : CONNECTION().getUrl();

    public static final String CA = CA();

    public static final String DUMMY = DUMMY();

    @SneakyThrows
    protected static String CA() {
        if (null != System.getenv("ptai.ca"))
            return IOUtils.toString(new FileInputStream(System.getenv("ptai.ca")), StandardCharsets.UTF_8);
        return getResourceString(CONNECTION().getCa());
    }

    @SneakyThrows
    protected static String DUMMY() {
        return getResourceString("keys/root-ca.dummy.org.pem");
    }
}
