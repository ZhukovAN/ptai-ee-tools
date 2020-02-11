package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.TestUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
public class FileCollectorTest {
    @TempDir
    protected static File tempFolder;

    protected static File sourcesFolder;
    protected static File destinationFolder;

    protected static List<FileCollector.FileEntry> entries;

    private static List<FileCollector.FileEntry> parseLog() {
        List<FileCollector.FileEntry> entries = new ArrayList<>();
        try {
            File logFile = TestUtils.getFileFromResources("log", "zip.verbose_log.txt");
            List<String> lines = new ArrayList<>();
            // Pattern for:
            // [PTAI] File /var/jenkins_home/workspace/Demo 2.0/SAST/code/code/FeedbackProject/FeedbackProject.xcodeproj/xcshareddata/xcschemes/Connect Enterprise (Staging).xcscheme added as code/FeedbackProject/FeedbackProject.xcodeproj/xcshareddata/xcschemes/Connect Enterprise (Staging).xcscheme
            Pattern pattern = Pattern.compile("^\\[PTAI\\] File /var/jenkins_home/workspace(.+) added as (.+)$");
            lines = Files.lines(logFile.toPath()).filter(pattern.asPredicate()).collect(Collectors.toList());
            for (String line : lines) {
                Matcher matcher = pattern.matcher(line);
                if (!matcher.find()) continue;
                String srcPath = matcher.group(1).replace("/", File.separator);
                String safeFilePath = sourcesFolder.getPath() + File.separator + TestUtils.getMd5(srcPath) + ".dat";
                FileCollector.FileEntry entry = new FileCollector.FileEntry(safeFilePath, srcPath);
                entries.add(entry);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return entries;
    }

    @BeforeAll
    static void init() {
        sourcesFolder = Paths.get(tempFolder.getPath() + File.separator + "in").toFile();
        destinationFolder = Paths.get(tempFolder.getPath() + File.separator + "out").toFile();
        entries = parseLog();

        try {
            for (FileCollector.FileEntry entry : entries) {
                Path path = Paths.get(entry.getFileName());
                if (!Files.exists(path.getParent()))
                    Files.createDirectories(path.getParent());
                if (!Files.exists(path))
                    Files.createFile(path);
                Files.write(path, entry.getEntryName().getBytes());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void collectSourcesFromLogData() {
        try {
            Transfers transfers = new Transfers();
            // transfers.add(Transfer.builder().includes("code/**/*").removePrefix("code").build());
            transfers.add(Transfer.builder()
                    .includes("Demo 2.0/SAST/code/**/*")
                    .removePrefix("Demo 2.0/SAST/code/code/")
                    .patternSeparator("[,]+").build());
            FileCollector collector = new FileCollector(transfers, null);
            File destFile = Paths.get(destinationFolder.getPath() + File.separator + "out.zip").toFile();
            collector.collect(sourcesFolder, destFile);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void collect() {
        try {
            Transfers transfers = new Transfers();
            // transfersJson.add(Transfer.xml().includes("**/*").build());
            transfers.add(Transfer.builder().includes("src/main/java/app01/**").build());
            transfers.add(Transfer.builder().includes("src/main/webapp/index.jsp").build());
            transfers.add(Transfer.builder().includes("pom.xml").build());
            FileCollector collector = new FileCollector(transfers, null);
            File srcFolder = new File("src\\test\\resources\\src\\app01");
            File destFile = File.createTempFile("PTAI_", ".zip");
            collector.collect(srcFolder, destFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    void packCollectedFiles() {
        Transfers transfers = new Transfers();
        // transfers.add(Transfer.builder().includes("code/**/*").removePrefix("code").build());
        FileCollector collector = Mockito.spy(new FileCollector(transfers, null));
        // doReturn(entries).when(collector).collectFiles(any(sourcesFolder.getClass()));
        Mockito.when(collector.collectFiles(any(sourcesFolder.getClass()))).thenReturn(entries);
        Path destFile = Paths.get(destinationFolder.getPath() + File.separator + "out.zip");
        collector.collect(sourcesFolder, destFile.toFile());
        System.out.println("Done");
    }
    @Test
    void research() {
        try {
            Transfers transfers = new Transfers();
            // transfersJson.add(Transfer.xml().includes("**/*").build());
            transfers.add(Transfer.builder().includes("**/*").build());
            FileCollector collector = new FileCollector(transfers, null);
            File srcFolder = new File("D:\\TEMP\\20200131\\app01");
            File destFile = new File("D:\\TEMP\\20200131\\test.zip");
            collector.collect(srcFolder, destFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}