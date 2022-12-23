package com.ptsecurity.misc.tools;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

import java.io.InputStream;
import java.util.logging.LogManager;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
public class BaseTest {
    @SneakyThrows
    @BeforeAll
    public static void init() {
        InputStream stream = getResourceStream("logging.properties");
        LogManager.getLogManager().readConfiguration(stream);
    }

    @BeforeEach
    public void pre(@NonNull final TestInfo testInfo) {
        log.info("Test started: {}", testInfo.getDisplayName());
    }
}
