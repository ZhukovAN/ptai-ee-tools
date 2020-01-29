package com.ptsecurity.appsec.ai.desktop.utils.report.generator;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class BuilderTest {

    @Test
    void execute() {
        try {
            String xml = new String(Files.readAllBytes(Paths.get("src\\test\\resources\\report.3.xml")));
            new Builder().execute(xml);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}