package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import org.junit.jupiter.api.Test;

public class StringFormatTest {
    @Test
    public void test() {
        String test = "Restore temp data started!" + "\r\n" + "Restore temp data 1%";
        String[] lines = test.split("\\r?\\n");
        for (String line : lines) {
            System.out.println(line);
            log("%s\r\n", line);
        }

    }

    protected void log(String format, Object... args) {
        System.out.print("[PTAI] " + String.format(format, args));
    }
}
