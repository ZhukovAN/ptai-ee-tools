package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.zip.Deflater;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@SuperBuilder
@NoArgsConstructor
public class ScanDataPacked extends com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked {
    public static final String DATA_FILE_NAME = "data.json";

    @NonNull
    public static String packData(@NonNull final Object data) throws GenericException {
        log.debug("Creating temporal file to serialize and pack data");
        try (
                TempFile jsonFile = TempFile.createFile();
                TempFile packedFile = TempFile.createFile();
                ZipArchiveOutputStream outputStream = new ZipArchiveOutputStream(packedFile.toFile());) {
            outputStream.setLevel(Deflater.BEST_COMPRESSION);
            log.debug("Storing data as JSON to file {}", jsonFile.toPath());
            call(() -> new ObjectMapper().writeValue(jsonFile.toFile(), data), "Object data serialization failed");

            log.debug("Data will be packed to {}", packedFile.toPath());
            log.debug("Adding packed file entry {}", DATA_FILE_NAME);
            call(() -> {
                ZipArchiveEntry entry = new ZipArchiveEntry(jsonFile.toFile(), DATA_FILE_NAME);
                outputStream.putArchiveEntry(entry);
                FileInputStream jsonFileStream = new FileInputStream(jsonFile.toFile());
                IOUtils.copy(jsonFileStream, outputStream);
                jsonFileStream.close();
                outputStream.closeArchiveEntry();
                outputStream.finish();
            }, "Adding packed file entry failed");
            outputStream.close();
            byte[] binaryData = call (() -> FileUtils.readFileToByteArray(packedFile.toFile()), "Packed data read failed");
            return Base64.getEncoder().encodeToString(binaryData);
        } catch (IOException e) {
            throw GenericException.raise("Packed file initialization failed", e);
        }
    }

    @NonNull
    @SuppressWarnings("unchecked")
    public static <T> T unpackData(@NonNull final String data, @NonNull final Class<?> clazz) throws GenericException {
        byte[] binary = Base64.getDecoder().decode(data);
        try (
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(binary);
                ZipArchiveInputStream inputStream = new ZipArchiveInputStream(byteArrayInputStream)) {
            do {
                ZipArchiveEntry entry = call(inputStream::getNextZipEntry, "Packed file entry enumeration failed");
                if (null == entry) break;
                if (entry.isDirectory()) continue;
                if (!DATA_FILE_NAME.equals(entry.getName())) continue;
                log.debug("Allocating {}-byte array to read data", entry.getSize());
                byte[] jsonData = new byte[(int) entry.getSize()];
                log.debug("Reading packed data");
                call(() -> IOUtils.read(inputStream, jsonData), "Packed data read failed");
                return call(() -> (T) new ObjectMapper().readValue(jsonData, clazz), "Packed object deserialization failed");
            } while (true);
            throw GenericException.raise("No packed data found", new IllegalArgumentException(data));
        } catch (IOException e) {
            throw GenericException.raise("Packed file initialization failed", e);
        }
    }

    public <T> T unpackData(@NonNull final Class<?> clazz) throws GenericException {
        return unpackData(data, clazz);
    }
}
