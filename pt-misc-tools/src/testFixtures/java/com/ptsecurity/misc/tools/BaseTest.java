package com.ptsecurity.misc.tools;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.logging.LogManager;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
public class BaseTest {
    @BeforeAll
    public static void init() {
    }

    @BeforeEach
    public void pre(@NonNull final TestInfo testInfo) {
        log.info("Test started: {}", testInfo.getDisplayName());
    }

    @NonNull
    public static String randomProjectName() {
        return randomProjectName("junit");
    }

    @NonNull
    public static String randomProjectName(@NonNull final String prefix) {
        String res = prefix + "-" + UUID.randomUUID();
        log.trace("Random project name {} generated", res);
        return res;
    }
}
