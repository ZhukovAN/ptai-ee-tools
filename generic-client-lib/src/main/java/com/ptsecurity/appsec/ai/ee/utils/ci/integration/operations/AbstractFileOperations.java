package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Slf4j
@SuperBuilder
@RequiredArgsConstructor
public abstract class AbstractFileOperations implements FileOperations {
    public abstract void saveArtifact(@NonNull String name, @NonNull File file);

    @SneakyThrows
    public void saveArtifact(@NonNull String name, byte[] data) {
        byte[] safeData = (null == data) ? new byte[0] : data;
        log.trace("Started: save in-memory data as build artifact {}. Data is {} bytes long", name, safeData.length);
        saveInMemoryData(name, safeData);
        log.trace("Finished: save in-memory data as build artifact {}. Data is {} bytes long", name, safeData.length);
    }

    @SneakyThrows
    @Deprecated
    public void saveArtifact(@NonNull String name, @NonNull final String data) {
        byte[] safeData = data.getBytes(StandardCharsets.UTF_8);
        log.trace("Started: save in-memory data as build artifact {}. Data is {} bytes long", name, safeData.length);
        saveInMemoryData(name, safeData);
        log.trace("Finished: save in-memory data as build artifact {}. Data is {} bytes long", name, safeData.length);
    }

    protected abstract void saveInMemoryData(@NonNull String name, byte[] data);
}
