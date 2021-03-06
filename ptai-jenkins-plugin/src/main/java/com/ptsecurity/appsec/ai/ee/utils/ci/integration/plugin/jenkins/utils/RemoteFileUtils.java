package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Objects;

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

        public BinaryReportSaver(@NonNull final String dir, @NonNull final String artifact, final byte[] data) {
            log.trace("Create binary report saver for {} artifact in {} folder", artifact, dir);
            this.dir = dir;
            this.artifact = artifact;
            this.data = (null == data) ? new byte[0] : Arrays.copyOf(data, data.length);
        }

        protected final String dir;
        protected final String artifact;

        @ToString.Exclude
        @NonNull
        private final byte[] data;

        public File execute() throws GenericException {
            try {
                Path destination = Paths.get(dir).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER).resolve(artifact);
                log.trace("Destination file path: {}", destination);
                String fileName = CallHelper.call(
                        () -> destination.getFileName().toString(),
                        "Empty destination file name");

                if (!destination.toFile().getParentFile().exists()) {
                    if (!destination.toFile().getParentFile().mkdirs())
                        throw new IOException("Failed to create folder structure for " + destination.toFile());
                }

                if (destination.toFile().exists()) {
                    log.warn("Existing report " + fileName + " will be overwritten");
                    if (!destination.toFile().delete())
                        log.error("Report " + fileName + " delete failed");
                }

                log.trace("In-memory data will be saved to {} file", destination);
                return Files.write(
                        destination,
                        data,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).toFile();
            } catch (IOException e) {
                throw GenericException.raise("Report file save failed", e);
            }
        }
    }
}
