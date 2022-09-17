package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.FileSaver;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AbstractFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;

@Slf4j
@SuperBuilder
@RequiredArgsConstructor
public class LocalFileOperations extends AbstractFileOperations implements FileOperations {
    @NonNull
    protected final FileSaver saver;

    @NonNull
    protected final TextOutput console;

    @Override
    @SneakyThrows
    protected void saveInMemoryData(@NonNull String name, byte[] data) {
        byte[] safeData = (null == data) ? new byte[0] : data;
        if (saver.getOutput().resolve(name).toFile().exists()) {
            console.warning("Existing file " + name + " will be overwritten");
            if (!saver.getOutput().resolve(name).toFile().delete()) {
                console.severe("Existing file " + name + " delete failed");
                return;
            }
        }
        FileUtils.writeByteArrayToFile(saver.getOutput().resolve(name).toFile(), safeData);
    }

    public void saveArtifact(@NonNull String name, @NonNull File file) {
        log.trace("Started: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
        CallHelper.call(() -> FileUtils.copyFile(file, saver.getOutput().resolve(name).toFile()), "Artifact file copy failed");
        log.trace("Finished: save {} file contents as build artifact {}", file.getAbsolutePath(), name);
    }


}
