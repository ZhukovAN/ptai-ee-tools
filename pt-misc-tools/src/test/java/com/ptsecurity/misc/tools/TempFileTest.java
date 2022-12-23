package com.ptsecurity.misc.tools;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
@DisplayName("Test temporary files / folders utils")
class TempFileTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Create temporary file")
    public void checkTempFile() {
        Path path;
        try (TempFile tempFile = TempFile.createFile()) {
            path = tempFile.toPath();
            assertTrue(path.toFile().exists());
        }
        assertFalse(path.toFile().exists());
    }

    @SneakyThrows
    @Test
    @DisplayName("Create temporary folder")
    public void checkTempFolder() {
        Path path;
        try (TempFile tempFolder = TempFile.createFolder()) {
            path = tempFolder.toPath();
            assertTrue(path.toFile().exists());
        }
        assertFalse(path.toFile().exists());
    }
}