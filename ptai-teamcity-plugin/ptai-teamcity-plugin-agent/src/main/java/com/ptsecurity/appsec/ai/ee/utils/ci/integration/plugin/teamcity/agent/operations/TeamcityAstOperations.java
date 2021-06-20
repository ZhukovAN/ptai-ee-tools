package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations;

import com.ptsecurity.appsec.ai.ee.scanresult.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.TeamcityAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.AstOperations;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.io.File;
import java.util.Map;
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

    public void scanStartedCallback(@NonNull final Project project, @NonNull UUID scanResultId) {
    }

    public void scanCompleteCallback(@NonNull final Project project, @NonNull final ScanResult scanResult)  {
    }

    public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
        return value;
    }
}
