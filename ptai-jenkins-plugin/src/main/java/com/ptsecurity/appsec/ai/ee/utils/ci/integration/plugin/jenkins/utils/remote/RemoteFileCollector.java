package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import hudson.remoting.Channel;
import jenkins.security.MasterToSlaveCallable;
import lombok.AllArgsConstructor;
import org.apache.commons.compress.archivers.ArchiveException;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;

public class RemoteFileCollector extends MasterToSlaveCallable<FilePath, PtaiClientException> {
    Executor executor;

    public FilePath collect(Launcher launcher, TaskListener listener, Transfers transfers, String srcFolderName, boolean verbose) throws InterruptedException, IOException, PtaiClientException {
        executor = new Executor(transfers, srcFolderName);
        executor.setConsoleLog(listener.getLogger());
        executor.setVerbose(verbose);

        return launcher.getChannel().call(this);
    }

    @Override
    public FilePath call() throws PtaiClientException {
        return new FilePath(executor.collect());
    }

    @AllArgsConstructor
    static class Executor extends Base implements Serializable {
        Transfers transfers;
        String srcFolderName;

        public File collect() throws PtaiClientException {
            return FileCollector.collect(transfers, new File(srcFolderName), this);
        }
    }
}
