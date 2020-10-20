package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Log
@RequiredArgsConstructor
public class RemoteFileUtils extends MasterToSlaveCallable<FilePath, ApiException> {
    protected final Executor executor;

    public static FilePath collect(Launcher launcher, TaskListener listener, Transfers transfers, String dir, boolean verbose) throws IOException, InterruptedException {
        Collector collector = new Collector(transfers, dir);
        collector.setConsole(listener.getLogger());
        collector.setVerbose(verbose);

        return launcher.getChannel().call(new RemoteFileUtils(collector));
    }

    public static FilePath saveReport(Launcher launcher, TaskListener listener, String dir, String artifact, byte[] data, boolean verbose) throws IOException, InterruptedException {
        BinaryReportSaver saver = new BinaryReportSaver(dir, artifact, data);
        saver.setConsole(listener.getLogger());
        saver.setVerbose(verbose);

        return launcher.getChannel().call(new RemoteFileUtils(saver));
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
                destination.toFile().getParentFile().mkdirs();
                return Files.write(
                        destination,
                        data.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).toFile();
            } catch (IOException e) {
                throw ApiException.raise("Report file save failed", e);
            }
        }
    }

    @RequiredArgsConstructor
    protected static class BinaryReportSaver extends Base implements Executor, Serializable {
        protected final String dir;
        protected final String artifact;
        protected final byte[] data;

        public File execute() throws ApiException {
            try {
                Path destination = Paths.get(dir).resolve(Base.DEFAULT_SAST_FOLDER).resolve(artifact);
                destination.toFile().getParentFile().mkdirs();
                if (destination.toFile().exists()) {
                    log.warning("Existing report " + destination.getFileName().toString() + " will be overwritten");
                    if (!destination.toFile().delete())
                        log.severe("Report " + destination.getFileName().toString() + " delete failed");
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
