package com.ptsecurity.appsec.ai.ee.server.integration.rest;

import com.ptsecurity.misc.tools.BaseTest;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.util.UUID;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

public abstract class BaseIT extends BaseTest {

    public static final String DUMMY_CA_PEM = DUMMY();

    @SneakyThrows
    protected static String DUMMY() {
        return getResourceString("keys/root-ca.dummy.org.pem");
    }
}
