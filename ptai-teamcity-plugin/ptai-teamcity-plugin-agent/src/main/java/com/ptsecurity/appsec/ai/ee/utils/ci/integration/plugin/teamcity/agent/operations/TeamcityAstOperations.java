package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.TeamcityAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.io.File;
import java.util.UUID;

@Builder
public class TeamcityAstOperations implements AstOperations {
    @NonNull
    protected final TeamcityAstJob owner;

    @SneakyThrows
    public File createZip() {
        Transfers transfers = new Transfers();

        for (Transfer transfer : owner.getTransfers())
            transfers.addTransfer(transfer);

        File zip = owner.getAgent().getBuildTempDirectory().toPath()
                .resolve(owner.getAgent().getProjectName())
                .resolve(owner.getAgent().getBuildTypeName())
                .resolve(owner.getAgent().getBuildNumber() + ".zip").toFile();
        FileCollector.collect(transfers, owner.getAgent().getCheckoutDirectory(), zip, owner);

        return zip;
    }

    public void scanStartedCallback(@NonNull final UUID projectId, @NonNull UUID scanResultId) {
    }

    @Override
    public void scanCompleteCallback(@NonNull final ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException {

    }
}
