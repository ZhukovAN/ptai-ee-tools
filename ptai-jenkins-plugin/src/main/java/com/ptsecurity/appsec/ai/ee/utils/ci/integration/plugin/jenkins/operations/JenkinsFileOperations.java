package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Files;

@Slf4j
@Builder
@RequiredArgsConstructor
public class JenkinsFileOperations implements FileOperations {
    /**
     * Jenkins AST job that provides Jenkins tools for AST to work. These
     * tools include event log listener, remote workspace etc.
     */
    @NonNull
    protected final JenkinsAstJob owner;

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File file) {
        log.trace("Saving artifact {} from {} file", name, file.getAbsolutePath());
        byte[] data = Files.readAllBytes(file.toPath());
        log.trace("Data load from {} file is completed", file.getAbsolutePath());
        saveArtifact(name, data);
    }

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull byte[] data) {
        log.trace("Save in-memory data as {} artifact. Data is {} bytes long", name, data.length);
        RemoteFileUtils.saveReport(owner.getLauncher(), owner.getListener(), owner.getWorkspace().getRemote(), name, data, owner.isVerbose());
    }
}
