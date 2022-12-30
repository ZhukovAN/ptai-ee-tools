package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import hudson.FilePath;
import hudson.model.TaskListener;
import hudson.remoting.RemoteOutputStream;
import jenkins.security.MasterToSlaveCallable;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.zip.Deflater;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector.bytesToString;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked.DATA_FILE_NAME;

@Slf4j
@RequiredArgsConstructor
public class RemoteFileUtils extends MasterToSlaveCallable<FilePath, GenericException> {
    protected final Executor executor;

    public static FilePath collect(
            @NonNull final JenkinsAstJob jenkinsAstJob) throws GenericException {
        Collector collector = new Collector(jenkinsAstJob);
        collector.setVerbose(jenkinsAstJob.isVerbose());

        return CallHelper.call(
                () -> Objects.requireNonNull(jenkinsAstJob.getLauncher().getChannel()).call(new RemoteFileUtils(collector)),
                "Remote file collect call failed");
    }

    @SuppressWarnings("UnusedReturnValue")
    public static FilePath saveReport(@NonNull final JenkinsAstJob jenkinsAstJob, String artifact, final byte[] data) throws GenericException {
        DataUploadTool saver = new DataUploadTool(jenkinsAstJob, artifact, data);
        log.trace("Started: save binary data as {} file to {} folder", artifact, jenkinsAstJob.getWorkspace().getRemote());
        FilePath result = CallHelper.call(
                () -> Objects.requireNonNull(jenkinsAstJob.getLauncher().getChannel()).call(new RemoteFileUtils(saver)),
                "Remote save report call failed");
        log.trace("Finished: save binary data as {} file to {} folder", artifact, jenkinsAstJob.getWorkspace().getRemote());
        return result;
    }

    @SuppressWarnings("UnusedReturnValue")
    public static FilePath saveReport(@NonNull final JenkinsAstJob jenkinsAstJob, String artifact, @NonNull final File data) throws GenericException {
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
                jenkinsAstJob.fine("Artifact %s packed from %s to %s", artifact, bytesToString(data.length()), bytesToString(archive.toFile().length()));

                final int maxChunkSize = jenkinsAstJob.getAdvancedSettings().getInt(AdvancedSettings.SettingInfo.JENKINS_DATA_CHUNK_SIZE);
                byte[] buffer = new byte[maxChunkSize];
                jenkinsAstJob.fine("Split %s file data into %s chunks", archive.toFile().getName(), bytesToString(maxChunkSize));
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
            int percent = 0;
            int currentFile = 0;
            List<FilePath> filePaths = new ArrayList<>();
            for (File file : parts) {
                log.trace("Read {} file contents", file);
                byte[] buffer = CallHelper.call(() -> FileUtils.readFileToByteArray(file), "File read failed");
                DataUploadTool saver = new DataUploadTool(jenkinsAstJob, buffer);
                saver.setVerbose(jenkinsAstJob.isVerbose());
                log.trace("Started: save binary data to remote temporary file");
                filePaths.add(CallHelper.call(
                        () -> Objects.requireNonNull(jenkinsAstJob.getLauncher().getChannel()).call(new RemoteFileUtils(saver)),
                        "Remote temporary file save call failed"));
                currentFile++;
                int currentPercent = Math.round(100f * currentFile / parts.size());
                if (percent != currentPercent) {
                    percent = currentPercent;
                    jenkinsAstJob.fine("Chunk files upload %s%%", currentPercent);
                }
                log.trace("Finished: save binary data to remote temporary file");
            }
            jenkinsAstJob.fine("Artifact %s merge and unpack started", artifact);
            FilePath result = CallHelper.call(
                    () -> {
                        UploadedDataMergeTool transaction = new UploadedDataMergeTool(jenkinsAstJob, artifact, filePaths);
                        return Objects.requireNonNull(jenkinsAstJob.getLauncher().getChannel()).call(new RemoteFileUtils(transaction));
                    },
                    "Remote file merge and unpack failed");
            jenkinsAstJob.fine("Artifact %s merge and unpack finished", artifact);
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

    @Slf4j
    @Getter
    @Setter
    protected abstract static class RemoteAbstractTool extends AbstractTool implements Executor, Serializable {
        public RemoteAbstractTool(@NonNull final JenkinsAstJob jenkinsAstJob) {
            super();
            listener = jenkinsAstJob.getListener();
            verbose = jenkinsAstJob.isVerbose();
        }

        protected final TaskListener listener;

        protected RemoteOutputStream remoteOutputStream;

        protected RemoteOutputStream getRemoteOutputStream() {
            if (null == remoteOutputStream)
                remoteOutputStream = new RemoteOutputStream(listener.getLogger());
            return remoteOutputStream;
        }

        @Override
        protected void out(final String value) {
            if (null == value) return;
            CallHelper.call(
                    () -> getRemoteOutputStream().write(((null == prefix ? value : prefix + value) + "\r\n").getBytes(StandardCharsets.UTF_8)),
                    "Remote console log output failed");
            if (null != console) console.println(null == prefix ? value : prefix + value);
        }

        @Override
        protected void out(final Throwable t) {
            if (null == t) return;
            StringWriter stringWriter = new StringWriter();
            t.printStackTrace(new PrintWriter(stringWriter));
            out(stringWriter.toString());
        }
    }

    protected static class Collector extends RemoteAbstractTool implements Executor, Serializable {
        public Collector(@NonNull final JenkinsAstJob jenkinsAstJob) {
            super(jenkinsAstJob);
            dir = jenkinsAstJob.getWorkspace().getRemote();

            transfers = new Transfers();
            for (Transfer transfer : jenkinsAstJob.getTransfers())
                transfers.addTransfer(Transfer.builder()
                        .excludes(jenkinsAstJob.replaceMacro(transfer.getExcludes()))
                        .flatten(transfer.isFlatten())
                        .useDefaultExcludes(transfer.isUseDefaultExcludes())
                        .includes(jenkinsAstJob.replaceMacro(transfer.getIncludes()))
                        .patternSeparator(transfer.getPatternSeparator())
                        .removePrefix(jenkinsAstJob.replaceMacro(transfer.getRemovePrefix()))
                        .build());

        }
        protected final Transfers transfers;
        protected final String dir;

        @SneakyThrows
        public File execute() throws GenericException {
            return FileCollector.collect(transfers, new File(dir), this);
        }
    }

    @ToString(callSuper = true)
    protected static class DataUploadTool extends RemoteAbstractTool implements Executor, Serializable {
        public DataUploadTool(@NonNull final JenkinsAstJob jenkinsAstJob, final byte[] data) {
            super(jenkinsAstJob);
            log.trace("Create binary report saver for temporary file");
            this.dir = null;
            this.artifact = null;
            this.data = (null == data) ? new byte[0] : Arrays.copyOf(data, data.length);
        }

        public DataUploadTool(@NonNull final JenkinsAstJob jenkinsAstJob, @NonNull final String artifact, final byte[] data) {
            super(jenkinsAstJob);
            log.trace("Create binary report saver for {} artifact in {} folder", artifact, jenkinsAstJob.getWorkspace().getRemote());
            this.dir = jenkinsAstJob.getWorkspace().getRemote();
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
    protected static class UploadedDataMergeTool extends RemoteAbstractTool implements Executor, Serializable {
        public UploadedDataMergeTool(@NonNull final JenkinsAstJob jenkinsAstJob, @NonNull final String artifact, @NonNull final List<FilePath> parts) {
            super(jenkinsAstJob);
            this.dir = jenkinsAstJob.getWorkspace().getRemote();
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
                        int percent = 0;
                        int currentFile = 0;
                        for (FilePath part : parts) {
                            log.trace("Start copy {} part file data", part.getName());
                            IOUtils.copy(part.read(), os);
                            currentFile++;
                            int currentPercent = Math.round(100f * currentFile / parts.size());
                            if (percent != currentPercent) {
                                percent = currentPercent;
                                fine("Chunk files merge %s%%", currentPercent);
                            }
                            log.trace("Delete {} part file data", part.getName());
                            part.delete();
                        }
                    }
                }, "File parts merge failed");

                Path destination = Paths.get(dir).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER).resolve(artifact);
                log.trace("Destination file path: {}", destination);
                DataUploadTool.check(destination);

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
                        fine("Artifact %s file saved", artifact);
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
