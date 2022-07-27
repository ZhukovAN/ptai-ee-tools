package com.ptsecurity.appsec.ai.ee.server.integration.rest.test;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;

public abstract class BaseIT extends BaseTest {

    public static final String DUMMY_CA_PEM = DUMMY();

    @SneakyThrows
    protected static String DUMMY() {
        return getResourceString("keys/root-ca.dummy.org.pem");
    }
}
