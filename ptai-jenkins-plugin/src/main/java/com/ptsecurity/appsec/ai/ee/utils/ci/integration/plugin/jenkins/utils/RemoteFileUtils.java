package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
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

@Slf4j
@RequiredArgsConstructor
public class RemoteFileUtils extends MasterToSlaveCallable<FilePath, ApiException> {
    protected final Executor executor;

    public static FilePath collect(Launcher launcher, TaskListener listener, Transfers transfers, String dir, boolean verbose) throws ApiException {
        Collector collector = new Collector(transfers, dir);
        collector.setConsole(listener.getLogger());
        collector.setVerbose(verbose);

        return Base.callApi(
                () -> launcher.getChannel().call(new RemoteFileUtils(collector)),
                "Remote file collect call failed");
    }

    public static FilePath saveReport(Launcher launcher, TaskListener listener, String dir, String artifact, final byte[] data, boolean verbose) throws ApiException {
        BinaryReportSaver saver = new BinaryReportSaver(dir, artifact, data);
        saver.setConsole(listener.getLogger());
        saver.setVerbose(verbose);
        return Base.callApi(
                () -> launcher.getChannel().call(new RemoteFileUtils(saver)),
                "Remote save report call failed");
    }

    @Override
    public FilePath call() throws ApiException {
        return new FilePath(executor.execute());
    }

    protected static interface Executor {
        public File execute() throws ApiException;
    }

    @RequiredArgsConstructor
    protected static class Collector extends Base implements Executor, Serializable {
        protected final Transfers transfers;
        protected final String dir;

        public File execute() throws ApiException {
            return FileCollector.collect(transfers, new File(dir), this);
        }
    }

    @RequiredArgsConstructor
    protected static class ReportSaver extends Base implements Executor, Serializable {
        protected final String dir;
        protected final String artifact;
        protected final String data;

        public File execute() throws ApiException {
            try {
                Path destination = Paths.get(dir).resolve(Base.DEFAULT_SAST_FOLDER).resolve(artifact);
                if (!destination.toFile().getParentFile().exists()) {
                    if (!destination.toFile().getParentFile().mkdirs())
                        throw new IOException("Failed to create folder structure for " + destination.toFile().toString());
                }
                return Files.write(
                        destination,
                        data.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).toFile();
            } catch (IOException e) {
                throw ApiException.raise("Report file save failed", e);
            }
        }
    }

    protected static class BinaryReportSaver extends Base implements Executor, Serializable {

        public BinaryReportSaver(@NonNull final String dir, @NonNull final String artifact, final byte[] data) {
            this.dir = dir;
            this.artifact = artifact;
            this.data = Arrays.copyOf(data, data.length);
        }

        protected final String dir;
        protected final String artifact;
        private final byte[] data;

        public File execute() throws ApiException {
            try {
                Path destination = Paths.get(dir).resolve(Base.DEFAULT_SAST_FOLDER).resolve(artifact);
                String fileName = Base.callApi(
                        () -> destination.getFileName().toString(),
                        "Empty destination file name");
                if (!destination.toFile().getParentFile().exists()) {
                    if (!destination.toFile().getParentFile().mkdirs())
                        throw new IOException("Failed to create folder structure for " + destination.toFile().toString());
                }
                if (destination.toFile().exists()) {
                    log.warn("Existing report " + fileName + " will be overwritten");
                    if (!destination.toFile().delete())
                        log.error("Report " + fileName + " delete failed");
                }

                return Files.write(
                        destination,
                        data,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).toFile();
            } catch (IOException e) {
                throw ApiException.raise("Report file save failed", e);
            }
        }
    }
}
