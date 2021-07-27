package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent.TeamcityAstJob;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

@Builder
@RequiredArgsConstructor
public class TeamcityFileOperations implements FileOperations {
    @NonNull
    protected final TeamcityAstJob owner;

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File file) {
        byte[] data = Files.readAllBytes(file.toPath());
        saveArtifact(name, data);
    }

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull byte[] data) {
        Path out = owner.getAgent().getBuildTempDirectory().toPath()
                .resolve(owner.getAgent().getProjectName())
                .resolve(owner.getAgent().getBuildTypeName());
        if (!out.toFile().exists())
            Files.createDirectories(out);
        out = out.resolve(name);

        if (out.toFile().exists()) {
            owner.warning("Existing file " + name + " will be overwritten");
            if (!out.toFile().delete()) {
                owner.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.writeByteArrayToFile(out.toFile(), data);
        owner.getArtifactsWatcher().addNewArtifactsPath(out.toString() + "=>" + AbstractJob.DEFAULT_OUTPUT_FOLDER);
    }
}
