package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;

class ServiceConfigurerIT {

    @SneakyThrows
    @Test
    void call() {
        final Path serverKeyFile = Paths.get(ServiceConfigurerIT.class.getClassLoader().getResource("keys/server.full.p12").toURI());
        final Path clientKeyFile = Paths.get(ServiceConfigurerIT.class.getClassLoader().getResource("keys/client.full.p12").toURI());
        final Path certFile = Paths.get(ServiceConfigurerIT.class.getClassLoader().getResource("keys/root.cer").toURI());

        int res = new CommandLine(new Plugin()).execute(
                "service-config",
                "--ptai-url", "https://ptai.domain.org:443",
                "--ci-url", "http://jenkins.domain.org",
                "--ci-token", "P@ssw0rd",
                "--server-keyfile", serverKeyFile.toString(),
                "--server-keyfile-password", "P@ssw0rd",
                "--server-key-password", "1q2w3e4r",
                "--client-keyfile", clientKeyFile.toString(),
                "--client-keyfile-password", "P@ssw0rd",
                "--client-key-password", "1q2w3e4r",
                // "--cert-file", certFile.toString(),
                "--master-token", "d5f0a836-cfaa-4a4c-bffb-d2b8ec8443a2",
                "--jar-file", "C:\\DATA\\DEVEL\\JAVA\\ptai-ee-tools\\ptai-ee-tools-java\\ptai-integration-service\\target\\ptai-integration-service-0.1-spring-boot.jar");
        Assertions.assertEquals(0, res);
    }
}