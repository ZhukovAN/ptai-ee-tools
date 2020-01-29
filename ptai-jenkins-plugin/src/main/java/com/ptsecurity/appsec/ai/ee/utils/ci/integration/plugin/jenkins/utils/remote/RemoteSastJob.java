package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import hudson.Launcher;
import jenkins.security.MasterToSlaveCallable;
import lombok.AllArgsConstructor;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@AllArgsConstructor
public class RemoteSastJob extends SastJob {
    protected Launcher launcher;

    @Override
    public void saveReport(String folder, String artifact, String data) throws IOException, InterruptedException {
        // folder parameter represents full folder to the file at remote (agent) host
        // Something like /home/user/workspace/TEST-SSDL/TEST-Project/report.html
        // So we need to execute file save on remote host
        new ReportSaver(folder, artifact, data).save(launcher);
    }

    @AllArgsConstructor
    static class ReportSaver extends MasterToSlaveCallable<Void, IOException> implements Serializable {
        String folder;
        String artifact;
        String data;

        public Void save(Launcher launcher) throws InterruptedException, IOException {
            return launcher.getChannel().call(this);
        }

        @Override
        public Void call() throws IOException {
            String fileName = folder + File.separator + artifact;
            new File(fileName).getParentFile().mkdirs();
            Files.write(
                    Paths.get(fileName),
                    data.getBytes("utf-8"),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            return null;
        }
    }
}
