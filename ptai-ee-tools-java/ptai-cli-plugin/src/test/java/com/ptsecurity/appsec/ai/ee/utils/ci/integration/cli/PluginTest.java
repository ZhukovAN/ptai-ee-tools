package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import org.junit.jupiter.api.Test;

class PluginTest {

    @Test
    void testMainSlimUiAst() {
        Plugin.main("slim-ui-ast", "--user=admin", "--token=cNaodFZZRqevd85L54Pa5NI4J0XNpO8d", "--truststore=src\\test\\resources\\keys\\trust.jks", "--truststore-pass=P@ssw0rd", "--url", "https://ptai.domain.org:8443/", "--project", "APP01", "--node", "PTAI", "--output", "C:\\DATA\\TEMP\\20200429\\out", "C:\\DATA\\TEMP\\20200429\\app01");
    }
}