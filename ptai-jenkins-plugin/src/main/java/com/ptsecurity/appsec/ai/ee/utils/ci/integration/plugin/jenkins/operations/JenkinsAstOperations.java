package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
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
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import hudson.FilePath;
import hudson.Util;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;

@Slf4j
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
    public void scanCompleteCallback(@NonNull ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException {
        ScanBriefDetailed scanBriefDetailed;
        if (scanBrief.getUseAsyncScan())
            scanBriefDetailed = ScanBriefDetailed.create(scanBrief, performance);
        else {
            GenericAstTasks genericAstTasks = new Factory().genericAstTasks(owner.getClient());
            log.debug("Getting full scan results for project:scan {}: {}", scanBrief.getProjectId(), scanBrief.getId());
            try {
                ScanResult scanResult = genericAstTasks.getScanResult(scanBrief);
                log.debug("Converting full scan results to detailed scan brief and storing it as job result");
                scanBriefDetailed = ScanBriefDetailed.create(scanResult, performance);
            } catch (GenericException e) {
                scanBriefDetailed = ScanBriefDetailed.create(scanBrief, performance);
            }
        }
        ScanDataPacked scanDataPacked = ScanDataPacked.builder()
                .type(SCAN_BRIEF_DETAILED)
                .data(ScanDataPacked.packData(scanBriefDetailed))
                .build();
        AstJobSingleResult action = new AstJobSingleResult(owner.getRun());
        action.setScanDataPacked(scanDataPacked);
        owner.getRun().addAction(action);
    }

    public String replaceMacro(@NonNull String value) {
        return replaceMacro(value, owner.getBuildInfo().getEnvVars());
    }

    public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
        return Util.replaceMacro(value, replacements);
    }
}
