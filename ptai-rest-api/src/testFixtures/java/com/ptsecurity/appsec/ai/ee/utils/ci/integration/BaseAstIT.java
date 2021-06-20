package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.io.*;
import java.nio.file.Path;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class BaseAstIT extends BaseIT {
    /**
     * Temporal folder where test sources will be unziipped to
     */
    protected Path SOURCES_FOLDER;
    /**
     * Temporal folder where reports will be generated to
     */
    protected Path REPORT_FOLDER;

    protected String NEW_PROJECT;

    /**
     * Method initializes subfolders in temp testing directory to store sources, reports, JSONs etc.
     */
    @BeforeAll
    public static void init() {
    }

    @AfterAll
    public static void fini() {
    }

    @SneakyThrows
    @BeforeEach
    public void pre() {
        SOURCES_FOLDER = TEMP_FOLDER.resolve("src");
        REPORT_FOLDER = TEMP_FOLDER.resolve(".ptai");
        NEW_PROJECT = "junit-" + UUID.randomUUID().toString();
        unzipTestSources("code/app01.zip", SOURCES_FOLDER);
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMP_FOLDER.toFile());
    }

    @SneakyThrows
    protected void unzipTestSources(final String resourceName, final Path destination) {
        File zip = new File(getClass().getClassLoader().getResource(resourceName).getFile());
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zip));
        ZipEntry entry = zis.getNextEntry();
        while (null != entry) {
            if (!entry.isDirectory()) {
                File out = new File(destination.resolve(entry.getName()).toString());
                out.getParentFile().mkdirs();
                OutputStream fos = new FileOutputStream(out);
                IOUtils.copy(zis, fos);
                fos.close();
            }
            entry = zis.getNextEntry();
        }
    }
}
