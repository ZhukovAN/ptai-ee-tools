package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.FileOperations;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.io.File;
import java.nio.file.Files;

@Builder
@RequiredArgsConstructor
public class JenkinsFileOperations implements FileOperations {
    /**
     * Jenkins AST job that provides Jenkins tools for AST to work. These tools include event log listener, remote workspace etc.
     *
     * @param owner New value for owner AST job
     */
    @NonNull
    protected final JenkinsAstJob owner;

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File file) {
        byte[] data = Files.readAllBytes(file.toPath());
        saveArtifact(name, data);
    }

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull byte[] data) {
        RemoteFileUtils.saveReport(owner.getLauncher(), owner.getListener(), owner.getWorkspace().getRemote(), name, data, owner.isVerbose());
    }
}
