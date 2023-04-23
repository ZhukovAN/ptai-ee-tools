package com.ptsecurity.misc.tools.helpers;

import com.ptsecurity.misc.tools.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
public class ArchiveHelper {
    /**
     * Method extracts packed resource file contents to temp folder. Currently, only 7-zip packed resources
     * are supported
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractResourceFile(@NonNull final String name) {
        return extractResourceFile(name, TempFile.createFolder().toPath());
    }

    /**
     * Method extracts packed resource file contents to temp folder. Currently, only 7-zip packed resources
     * are supported
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractResourceFile(@NonNull final String name, @NonNull final Path destinationFolder) {
        if (name.endsWith(".7z"))
            return extract7ZipResourceFile(name, destinationFolder);
        else if (name.endsWith(".zip"))
            return extractZipResourceFile(name, destinationFolder);
        else
            throw new IllegalArgumentException("Unsupported packed file " + name);
    }

    /**
     * Method extracts 7z-packed resource file contents to temp folder
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extract7ZipResourceFile(@NonNull final String name) {
        return extract7ZipResourceFile(name, TempFile.createFolder().toPath());
    }

    /**
     * Method extracts 7z-packed resource file contents to temp folder
     * @param name Absolute name of resource
     * @param destinationFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extract7ZipResourceFile(@NonNull final String name, @NonNull final Path destinationFolder) {
        Path res = null;

        // As 7zip needs random access to packed file, there's no direct way to use
        // InputStream: we are allowed to use File or SeekableByteChannel only. So we
        // need to copy resource contents to auto-closeable temp file
        try (TempFile tempResourceFile = TempFile.createFile()) {
            InputStream is = getResourceStream(name);
            FileUtils.copyInputStreamToFile(is, tempResourceFile.toFile());
            SevenZFile packedFile = new SevenZFile(tempResourceFile.toFile());
            byte[] buffer = new byte[1024];

            SevenZArchiveEntry entry = packedFile.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = destinationFolder.resolve(entry.getName()).toFile();

                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : destinationFolder;

                    if (!out.getParentFile().exists() && !out.getParentFile().mkdirs()) throw new IOException("Failed to create directory " + out.getParentFile());

                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        do {
                            int dataRead = packedFile.read(buffer);
                            if (-1 == dataRead || 0 == dataRead) break;
                            fos.write(buffer, 0, dataRead);
                        } while (true);
                    }
                }
                entry = packedFile.getNextEntry();
            }
            packedFile.close();
        }
        return res;
    }

    /**
     * Method extracts zip-packed resource file contents to temp folder
     * @param name Absolute name of resource like "code/php-smoke.zip"
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public Path extractZipResourceFile(@NonNull final String name) {
        return extractZipResourceFile(name, TempFile.createFolder().toPath());
    }

    /**
     * Method extracts zip-packed resource file contents to temp folder
     * @param name Absolute name of resource like "code/php-smoke.zip"
     * @param destinationFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractZipResourceFile(@NonNull final String name, final Path destinationFolder) {
        return extractZipStream(getResourceStream(name), destinationFolder);
    }

    /**
     * Method extracts zip-packed stream contents to folder
     * @param stream Absolute name of resource like "code/php-smoke.zip"
     * @param destinationFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractZipStream(@NonNull final InputStream stream, final Path destinationFolder) {
        Path res = null;
        try (
                ZipInputStream zis = new ZipInputStream(stream)) {
            ZipEntry entry = zis.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = destinationFolder.resolve(entry.getName()).toFile();
                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : destinationFolder;
                    if (!out.getParentFile().exists() && !out.getParentFile().mkdirs()) throw new IOException("Failed to create directory " + out.getParentFile());
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        IOUtils.copy(zis, fos);
                    }
                }
                entry = zis.getNextEntry();
            }
        }
        return res;
    }

    /**
     * Method packs byte array to file using 7zip method
     * @param path File path where packed data is to be saved
     * @param data Byte array to be packed
     */
    @SneakyThrows
    public static void packData7Zip(@NonNull final Path path, final byte[] data) {
        String name = path.getFileName().toString().trim();
        if (name.endsWith(".7z"))
            name = name.substring(0, name.length() - ".7z".length());
        packData7Zip(path, name, data);
    }

    /**
     * Method packs byte array to file using 7zip method
     * @param path File path where packed data is to be saved
     * @param data Byte array to be packed
     */
    @SneakyThrows
    public static void packData7Zip(@NonNull final Path path, @NonNull final String data) {
        packData7Zip(path, data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Method packs byte array to file using 7zip method
     * @param path File path where packed data is to be saved
     * @param name Archived data entry name
     * @param data Byte array to be packed
     */
    @SneakyThrows
    public static void packData7Zip(@NonNull final Path path, @NonNull final String name, final byte[] data) {
        if (!path.toFile().exists()) Files.createFile(path);
        try (SevenZOutputFile zip = new SevenZOutputFile(path.toFile())) {
            SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName(name);
            entry.setDirectory(false);
            entry.setLastModifiedDate(new Date());
            entry.setSize(data.length);
            zip.putArchiveEntry(entry);
            zip.write(data);
            zip.closeArchiveEntry();
        }
    }

    @SneakyThrows
    public static String extract7ZipString(final byte[] data) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        SevenZFile packedFile = new SevenZFile(new SeekableInMemoryByteChannel(data));
        byte[] buffer = new byte[1024];

        SevenZArchiveEntry entry = packedFile.getNextEntry();
        while (null != entry) {
            if (entry.isDirectory()) {
                log.trace("Skip {} entry as is is a directory", entry.getName());
                entry = packedFile.getNextEntry();
                continue;
            }
            do {
                int dataRead = packedFile.read(buffer);
                if (-1 == dataRead || 0 == dataRead) break;
                result.write(buffer, 0, dataRead);
            } while (true);
            return result.toString();
        }
        return null;
    }

    private static void packDataZip(ZipArchiveOutputStream out, File file, String name) throws IOException {
        log.trace("Zip {} file as {}", file.getName(), name);
        ZipArchiveEntry zipArchiveEntry = new ZipArchiveEntry(file, name);
        out.putArchiveEntry(zipArchiveEntry);
        if (file.isFile()) {
            log.trace("Pack data from file");
            try (FileInputStream fis = new FileInputStream(file)) {
                IOUtils.copy(fis, out);
                out.closeArchiveEntry();
            }
        } else {
            out.closeArchiveEntry();
            log.trace("Pack children files / folders");
            File[] files = file.listFiles();
            if (null == files) return;
            for (File child : files)
                packDataZip(out, child, name + "/" + child.getName());
        }
    }

    /**
     * Pack file or folder contents to temporary file
     * @param source File or folder path that is to be zipped
     * @return Temporary file location
     */
    @SneakyThrows
    public static Path packDataZip(@NonNull final Path source) {
        Path zip = TempFile.createFile().toPath();
        log.trace("File(s) from {} will be zipped to {}", source.getFileName(), zip.getFileName());
        try (
                OutputStream os = Files.newOutputStream(zip);
                BufferedOutputStream bos = new BufferedOutputStream(os);
                ZipArchiveOutputStream zos = new ZipArchiveOutputStream(bos)) {
            if (source.toFile().isDirectory()) {
                File[] files = source.toFile().listFiles();
                if (null == files) return zip;
                for (File file : files)
                    packDataZip(zos, file, file.getName());
            } else {
                packDataZip(zos, source.toFile(), source.getFileName().toString());
            }
        }
        return zip;
    }
}
