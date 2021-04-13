package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils.GracefulShutdown;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.AstOperations;
import lombok.Builder;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

@Builder
public class LocalAstOperations implements AstOperations {
    @NonNull
    protected final CliAstJob owner;

    private GracefulShutdown shutdown;

    /** Creates local zip archive from files defined by transfers. This utility method is
     * to be called in @createZip implementations for AstJob descendants that aren't require
     * special remote file processing techniques. For example, for Jenkins plugin @createZip
     * implementation must be defferent from default one and use MasterToSlaveCallable
     * approach to zip sources locally on the build agents
     * @param transfers Defines what are the files to be zipped
     * @param input Folder where files to be zipped are located
     * @return Zip archive with sources ready to be uploaded to PT AI server
     */
    private File createLocalZip(@NonNull final Transfers transfers, @NonNull final Path input) throws ApiException {
        return FileCollector.collect(transfers, input.toFile(), owner);
    }

    public File createZip() throws ApiException {
        Transfer transfer = new Transfer();
        if (StringUtils.isNotEmpty(owner.getIncludes())) transfer.setIncludes(owner.getIncludes());
        if (StringUtils.isNotEmpty(owner.getExcludes())) transfer.setExcludes(owner.getExcludes());
        transfer.setUseDefaultExcludes(owner.isUseDefaultExcludes());
        return createLocalZip(new Transfers().addTransfer(transfer), owner.getInput());
    }

    public void scanStartedCallback(@NonNull final Project project, @NonNull UUID scanResultId) {
        shutdown = new GracefulShutdown(owner);
        Runtime.getRuntime().addShutdownHook(shutdown);
    }

    public void scanCompleteCallback()  {
        if (null != shutdown) shutdown.setStopped(true);
    }

    public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
        return value;
    }
}
