package com.ptsecurity.misc.tools.helpers;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
public class ResourcesHelper {
    /**
     * Method returns InputStream that allows to read resource data
     * @param name Absolute (as {@link ClassLoader#getResourceAsStream(String)} used) name of resource
     * @return InputStream where resource data is to be read from
     */
    @SneakyThrows
    @NonNull
    public static InputStream getResourceStream(@NonNull final String name) {
        return Objects.requireNonNull(ResourcesHelper.class.getClassLoader().getResourceAsStream(name));
    }

    @SneakyThrows
    @NonNull
    public static String getResourceString(@NonNull final String name) {
        log.trace("Load {} string from resources", name);
        InputStream inputStream = Objects.requireNonNull(ResourcesHelper.class.getClassLoader().getResourceAsStream(name));
        return IOUtils.toString(inputStream, StandardCharsets.UTF_8);
    }

    @SneakyThrows
    @NonNull
    public static String getResource7ZipString(@NonNull final String name) {
        log.trace("Load {} 7zip-packed string from resources", name);
        byte[] data = IOUtils.resourceToByteArray(name, ResourcesHelper.class.getClassLoader());
        return Objects.requireNonNull(ArchiveHelper.extract7ZipString(data));
    }
}
