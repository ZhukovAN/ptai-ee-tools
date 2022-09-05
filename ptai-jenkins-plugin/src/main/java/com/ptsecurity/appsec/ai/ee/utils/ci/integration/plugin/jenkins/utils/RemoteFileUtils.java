package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.TempFile;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.zip.Deflater;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector.bytesToString;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked.DATA_FILE_NAME;

@Slf4j
@RequiredArgsConstructor
public class RemoteFileUtils extends MasterToSlaveCallable<FilePath, GenericException> {
    protected final Executor executor;

    public static FilePath collect(
            @NonNull final Launcher launcher,
            @NonNull final TaskListener listener,
            Transfers transfers,
            String dir,
            boolean verbose) throws GenericException {
        Collector collector = new Collector(transfers, dir);
        collector.setConsole(listener.getLogger());
        collector.setVerbose(verbose);

        return CallHelper.call(
                () -> Objects.requireNonNull(launcher.getChannel()).call(new RemoteFileUtils(collector)),
                "Remote file collect call failed");
    }

    @SuppressWarnings("UnusedReturnValue")
    public static FilePath saveReport(Launcher launcher, TaskListener listener, String dir, String artifact, final byte[] data, boolean verbose) throws GenericException {
        BinaryReportSaver saver = new BinaryReportSaver(dir, artifact, data);
        saver.setConsole(listener.getLogger());
        saver.setVerbose(verbose);
        log.trace("Started: save binary data as {} file to {} folder", artifact, dir);
        FilePath result = CallHelper.call(
                () -> Objects.requireNonNull(launcher.getChannel()).call(new RemoteFileUtils(saver)),
                "Remote save report call failed");
        log.trace("Finished: save binary data as {} file to {} folder", artifact, dir);
        return result;
    }

    @SuppressWarnings("UnusedReturnValue")
    public static FilePath saveReport(Launcher launcher, TaskListener listener, String dir, String artifact, @NonNull final File data, boolean verbose) throws GenericException {
        try (
                TempFile tempFolder = TempFile.createFolder();
                TempFile archive = TempFile.createFile(tempFolder.toPath()) ) {
            log.trace("Temporary folder {} created for packed file operations", tempFolder.toPath());
            List<File> parts = CallHelper.call(() -> {
                List<File> files = new ArrayList<>();
                log.trace("File {} pack started", data);
                try (
                        ZipArchiveOutputStream zip = new ZipArchiveOutputStream(archive.toFile());
                        FileInputStream is = new FileInputStream(data) ) {
                    log.trace("Pack {} file data into {}", data, archive);
                    zip.setLevel(Deflater.BEST_COMPRESSION);
                    ZipArchiveEntry entry = new ZipArchiveEntry(data, DATA_FILE_NAME);
                    zip.putArchiveEntry(entry);
                    IOUtils.copy(is, zip);
                    is.close();
                    zip.closeArchiveEntry();
                    zip.finish();
                }
                log.trace("File {} pack finished", data);
                log.trace("Initial data file size is {}, packed to {}", bytesToString(data.length()), bytesToString(archive.toFile().length()));

                final int maxChunkSize = 1 * 1024;
                byte[] buffer = new byte[maxChunkSize];
                log.trace("Split {} file data into {} bytes chunks", archive, maxChunkSize);
                long totalChunksNumber = archive.toFile().length() / maxChunkSize;
                if (archive.toFile().length() > maxChunkSize * totalChunksNumber) totalChunksNumber++;
                int digitsInChunkNumber = (int)(Math.ceil(Math.log10(totalChunksNumber)));

                try (FileInputStream is = new FileInputStream(archive.toFile())) {
                    int chunkNumber = 0;
                    long totalBytesToRead = archive.toFile().length();
                    while (totalBytesToRead > 0) {
                        int bytesToRead = totalBytesToRead > maxChunkSize ? maxChunkSize : (int) totalBytesToRead;
                        int bytesActuallyRead = is.read(buffer, 0, bytesToRead);
                        if (bytesActuallyRead != bytesToRead) log.warn("Bytes to read: {}, but actually {} bytes read", bytesToRead, bytesActuallyRead);
                        totalBytesToRead -= bytesActuallyRead;
                        String chunkFileName = "data.zip.part." + StringUtils.leftPad(String.valueOf(chunkNumber), digitsInChunkNumber, "0");
                        Path chunkPath = tempFolder.toPath().resolve(chunkFileName);

                        try (FileOutputStream os = new FileOutputStream(chunkPath.toFile())) {
                            os.write(buffer, 0, bytesToRead);
                            os.flush();
                        }
                        files.add(chunkPath.toFile());
                        log.trace("Chunk file {} saved", chunkFileName);
                        chunkNumber++;
                    }
                }
                return files;
            }, "Data file multipart archive create failed");
            log.trace("Start file parts processing");
            List<FilePath> filePaths = new ArrayList<>();
            for (File file : parts) {
                log.trace("Read {} file contents", file);
                byte[] buffer = CallHelper.call(() -> FileUtils.readFileToByteArray(file), "File read failed");
                BinaryReportSaver saver = new BinaryReportSaver(buffer);
                saver.setConsole(listener.getLogger());
                saver.setVerbose(verbose);
                log.trace("Started: save binary data to remote temporary file");
                filePaths.add(CallHelper.call(
                        () -> Objects.requireNonNull(launcher.getChannel()).call(new RemoteFileUtils(saver)),
                        "Remote temporary file save call failed"));
                log.trace("Finished: save binary data to remote temporary file");
            }
            log.trace("Started: merge and unpack remote file");
            FilePath result = CallHelper.call(
                    () -> {
                        BinaryChunkSaverTransaction transaction = new BinaryChunkSaverTransaction(dir, artifact, filePaths);
                        return Objects.requireNonNull(launcher.getChannel()).call(new RemoteFileUtils(transaction));
                    },
                    "Remote file merge and unpack failed");
            log.trace("Finished: merge and unpack remote file");
            return result;
        }
    }

    @Override
    public FilePath call() throws GenericException {
        return new FilePath(executor.execute());
    }

    protected interface Executor {
        File execute() throws GenericException;
    }

    @RequiredArgsConstructor
    protected static class Collector extends AbstractTool implements Executor, Serializable {
        protected final Transfers transfers;
        protected final String dir;

        public File execute() throws GenericException {
            return FileCollector.collect(transfers, new File(dir), this);
        }
    }

    @ToString(callSuper = true)
    protected static class BinaryReportSaver extends AbstractTool implements Executor, Serializable {
        public BinaryReportSaver(final byte[] data) {
            log.trace("Create binary report saver for temporary file");
            this.dir = null;
            this.artifact = null;
            this.data = (null == data) ? new byte[0] : Arrays.copyOf(data, data.length);
        }

        public BinaryReportSaver(@NonNull final String dir, @NonNull final String artifact, final byte[] data) {
            log.trace("Create binary report saver for {} artifact in {} folder", artifact, dir);
            this.dir = dir;
            this.artifact = artifact;
            this.data = (null == data) ? new byte[0] : Arrays.copyOf(data, data.length);
        }

        protected final String dir;
        protected final String artifact;

        @ToString.Exclude
        private final byte[] data;

        public File execute() throws GenericException {
            try {
                Path destination;
                if (null != dir && null != artifact) {
                    destination = Paths.get(dir).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER).resolve(artifact);
                    check(destination);
                } else
                    destination = TempFile.createFile().toPath();
                log.trace("Destination file path: {}", destination);

                log.trace("In-memory data will be saved to {} file", destination);
                return Files.write(
                        destination,
                        data,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).toFile();
            } catch (IOException e) {
                throw GenericException.raise("Report file save failed", e);
            }
        }

        public static void check(@NonNull final Path destination) throws GenericException {
            CallHelper.call(() -> {
                String fileName = Objects.requireNonNull(destination.getFileName()).toString();

                if (!destination.toFile().getParentFile().exists()) {
                    if (!destination.toFile().getParentFile().mkdirs())
                        throw new IOException("Failed to create folder structure for " + destination.toFile());
                }

                if (destination.toFile().exists()) {
                    log.warn("Existing report " + fileName + " will be overwritten");
                    if (!destination.toFile().delete())
                        log.error("Report " + fileName + " delete failed");
                }
            }, "Destination file check failed");
        }
    }

    @ToString(callSuper = true)
    protected static class BinaryChunkSaverTransaction extends AbstractTool implements Executor, Serializable {
        public BinaryChunkSaverTransaction(@NonNull final String dir, @NonNull final String artifact, @NonNull final List<FilePath> parts) {
            this.dir = dir;
            this.artifact = artifact;
            this.parts = parts;
        }

        protected final String dir;
        protected final String artifact;

        @ToString.Exclude
        private final List<FilePath> parts;

        public File execute() throws GenericException {
            try (TempFile archive = TempFile.createFile()) {
                CallHelper.call(() -> {
                    try (FileOutputStream os = new FileOutputStream(archive.toFile())) {
                        log.trace("Merge parts into {} archive", archive);
                        for (FilePath part : parts) {
                            log.trace("Start copy {} part file data", part.getName());
                            IOUtils.copy(part.read(), os);
                            log.trace("Delete {} part file data", part.getName());
                            part.delete();
                        }
                    }
                }, "File parts merge failed");

                Path destination = Paths.get(dir).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER).resolve(artifact);
                log.trace("Destination file path: {}", destination);
                BinaryReportSaver.check(destination);

                log.trace("Unpack {} file as {} / {} artifact ", archive, dir, artifact);
                try (
                        FileInputStream fis = new FileInputStream(archive.toFile());
                        ZipArchiveInputStream inputStream = new ZipArchiveInputStream(fis)) {
                    ZipArchiveEntry entry = CallHelper.call(inputStream::getNextZipEntry, "Packed file entry enumeration failed");
                    if (null == entry) {
                        log.error("No entries in {} file", archive);
                        throw GenericException.raise("No entries in archive", new IllegalArgumentException());
                    }
                    if (entry.isDirectory()) {
                        log.error("Invalid entry type in {} file", archive);
                        throw GenericException.raise("Invalid archive entry type", new IllegalArgumentException());
                    }
                    if (!DATA_FILE_NAME.equals(entry.getName())) {
                        log.error("Invalid entry name {} in {} file", entry.getName(), archive);
                        throw GenericException.raise("Invalid archive entry name", new IllegalArgumentException());
                    }
                    byte[] buffer = new byte[1024];
                    try (FileOutputStream fos = new FileOutputStream(destination.toFile())) {
                        do {
                            int dataRead = inputStream.read(buffer);
                            if (-1 == dataRead || 0 == dataRead) break;
                            fos.write(buffer, 0, dataRead);
                        } while (true);
                    }
                }
                log.trace("File unpack finished");
                return destination.toFile();
            } catch (IOException e) {
                throw GenericException.raise("Multipart data file save failed", e);
            }
        }
    }
}
