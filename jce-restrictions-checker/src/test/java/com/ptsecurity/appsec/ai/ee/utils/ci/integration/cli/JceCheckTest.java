package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JceCheckTest {

    @Test
    void main() {
        JceCheck.main(new String[] {
                "--keystore=src\\test\\resources\\keystore.pkcs8.pem",
                "--keystore-pass=P@ssw0rd"
        });
    }
}