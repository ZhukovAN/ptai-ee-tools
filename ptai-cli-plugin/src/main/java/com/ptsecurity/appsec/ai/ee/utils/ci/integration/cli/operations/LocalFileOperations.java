package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.FileSaver;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
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
    protected final FileSaver saver;

    @NonNull
    protected final TextOutput console;

    @SneakyThrows
    public void saveArtifact(@NonNull String name, @NonNull File data) {
        if (saver.getOutput().resolve(name).toFile().exists()) {
            console.warning("Existing file " + name + " will be overwritten");
            if (!saver.getOutput().resolve(name).toFile().delete()) {
                console.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.moveFile(data, saver.getOutput().resolve(name).toFile());
    }

    @SneakyThrows
    public void saveArtifact(@NonNull String name, byte[] data) {
        if (saver.getOutput().resolve(name).toFile().exists()) {
            console.warning("Existing file " + name + " will be overwritten");
            if (!saver.getOutput().resolve(name).toFile().delete()) {
                console.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.writeByteArrayToFile(saver.getOutput().resolve(name).toFile(), data);
    }
}
