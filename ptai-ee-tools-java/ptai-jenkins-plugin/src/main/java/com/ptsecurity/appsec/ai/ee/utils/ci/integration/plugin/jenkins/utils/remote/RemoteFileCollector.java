package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import jenkins.security.MasterToSlaveCallable;
import lombok.AllArgsConstructor;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;

/**
 * Class collects files on a Jenkins node (both master and remotes due to
 * MasterToSlaveCallable inheritance) and returns FilePath to resulting zip archive
 */
public class RemoteFileCollector extends MasterToSlaveCallable<FilePath, ApiException> {
    Executor executor;

    public FilePath collect(Launcher launcher, TaskListener listener, Transfers transfers, String folder, boolean verbose) throws InterruptedException, IOException, ApiException {
        executor = new Executor(transfers, folder);
        executor.setConsole(listener.getLogger());
        executor.setVerbose(verbose);

        return launcher.getChannel().call(this);
    }

    @Override
    public FilePath call() throws ApiException {
        return new FilePath(executor.collect());
    }

    @AllArgsConstructor
    static class Executor extends Base implements Serializable {
        Transfers transfers;
        String srcFolderName;

        public File collect() throws ApiException {
            return FileCollector.collect(transfers, new File(srcFolderName), this);
        }
    }
}
