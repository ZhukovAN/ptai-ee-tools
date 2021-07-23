package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.server.api.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.AstOperations;
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
            transfers.addTransfer(com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer.builder()
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

    public void scanStartedCallback(@NonNull final UUID projectId, @NonNull UUID scanResultId) throws ApiException {
    }

    public void scanCompleteCallback(@NonNull final ScanResult scanResult) throws ApiException {
        Run<?, ?> run = owner.getRun();
        AstJobSingleResult astJobSingleResult = new AstJobSingleResult(run);
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
