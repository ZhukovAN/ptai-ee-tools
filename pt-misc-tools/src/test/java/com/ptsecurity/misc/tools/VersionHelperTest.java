package com.ptsecurity.misc.tools;

import com.ptsecurity.misc.tools.helpers.VersionHelper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@DisplayName("Test version numbers compare function")
class VersionHelperTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Compare versions")
    public void compareVersions() {
        assertEquals(0, VersionHelper.compare(
                Arrays.asList(1, 0, 0),
                Arrays.asList(1, 0, 0)));
        assertEquals(-1, VersionHelper.compare(
                Arrays.asList(1, 0, 0),
                Arrays.asList(1, 0, 1)));
        assertEquals(1, VersionHelper.compare(
                Arrays.asList(1, 0, 2),
                Arrays.asList(1, 0, 1)));
        assertEquals(1, VersionHelper.compare(
                Arrays.asList(1, 0, 1, 1),
                Arrays.asList(1, 0, 1)));
        assertEquals(1, VersionHelper.compare(
                Arrays.asList(2, 0, 1),
                Arrays.asList(1, 9, 9, 9999)));
    }
}