package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import hudson.FilePath;
import hudson.Util;
import hudson.model.Run;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.UUID;

@Builder
public class JenkinsAstOperations implements AstOperations {

    /**
     * Jenkins AST job that provides Jenkins tools for AST to work. These tools
     * include event log listener, remote workspace etc.     *
     * @param owner New value for owner AST job
     */
    @NonNull
    protected final JenkinsAstJob owner;

    @SneakyThrows
    public File createZip() {
        Transfers transfers = new Transfers();

        for (com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Transfer transfer : owner.getTransfers())
            transfers.addTransfer(Transfer.builder()
                    .excludes(replaceMacro(transfer.getExcludes()))
                    .flatten(transfer.isFlatten())
                    .useDefaultExcludes(transfer.isUseDefaultExcludes())
                    .includes(replaceMacro(transfer.getIncludes()))
                    .patternSeparator(transfer.getPatternSeparator())
                    .removePrefix(replaceMacro(transfer.getRemovePrefix()))
                    .build());
        // Upload project sources
        FilePath remoteZip = RemoteFileUtils.collect(owner.getLauncher(), owner.getListener(), transfers, owner.getWorkspace().getRemote(), owner.isVerbose());
        File zip = FileCollector.createTempFile();
        try (OutputStream fos = new FileOutputStream(zip)) {
            remoteZip.copyTo(fos);
            remoteZip.delete();
        }
        return zip;
    }

    @Override
    public void scanStartedCallback(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {

    }

    @Override
    public void scanCompleteCallback(@NonNull ScanBrief scanBrief) throws GenericException {
        Run<?, ?> run = owner.getRun();
        AstJobSingleResult astJobSingleResult = new AstJobSingleResult(run);

        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(owner.getClient());
        ScanResult scanResult = genericAstTasks.getScanResult(scanBrief.getProjectId(), scanBrief.getId());
        astJobSingleResult.setScanResult(scanResult);
        run.addAction(astJobSingleResult);
    }

    public String replaceMacro(@NonNull String value) {
        return replaceMacro(value, owner.getBuildInfo().getEnvVars());
    }

    public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
        return Util.replaceMacro(value, replacements);
    }
}
