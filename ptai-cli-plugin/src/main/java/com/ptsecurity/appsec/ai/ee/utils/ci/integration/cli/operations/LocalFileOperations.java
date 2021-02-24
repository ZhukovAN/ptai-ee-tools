package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.FileOperations;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;

import java.io.File;

@Builder
@RequiredArgsConstructor
public class LocalFileOperations implements FileOperations {
    @NonNull
    protected final CliAstJob owner;

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File data) {
        if (owner.getOutput().resolve(name).toFile().exists()) {
            owner.warning("Existing file " + name + " will be overwritten");
            if (!owner.getOutput().resolve(name).toFile().delete()) {
                owner.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.moveFile(data, owner.getOutput().resolve(name).toFile());
    }

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull byte[] data) {
        if (owner.getOutput().resolve(name).toFile().exists()) {
            owner.warning("Existing file " + name + " will be overwritten");
            if (!owner.getOutput().resolve(name).toFile().delete()) {
                owner.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.writeByteArrayToFile(owner.getOutput().resolve(name).toFile(), data);
    }
}
