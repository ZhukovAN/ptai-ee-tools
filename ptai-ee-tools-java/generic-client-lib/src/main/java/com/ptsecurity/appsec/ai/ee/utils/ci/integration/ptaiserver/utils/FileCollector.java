package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import lombok.*;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.FileSet;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@RequiredArgsConstructor
public class FileCollector {
    static Method getScannedDirs;
    static {
        Class c = null;
        try {
            c = Class.forName("org.apache.tools.ant.DirectoryScanner");
            getScannedDirs = c.getDeclaredMethod("getScannedDirs", null);
            getScannedDirs.setAccessible(true);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            getScannedDirs = null;
        }
    }

    @SneakyThrows
    protected String[] getScannedDirs(DirectoryScanner ds) {
        Set<String> res = (Set<String>) getScannedDirs.invoke(ds);
        return res.stream().toArray(String[] ::new);
    }

    @AllArgsConstructor
    @Getter
    public static class FileEntry {
        private final String fileName;
        private final String entryName;
    }

    private final Transfers transfers;
    private final Base owner;

    public void collect(final File srcDir, final File destFile) throws PtaiClientException {
        List<FileEntry> fileEntries = this.collectFiles(srcDir);
        try {
            this.packCollectedFiles(destFile, fileEntries);
        } catch (ArchiveException | IOException e) {
            throw new PtaiClientException("File collect error", e);
        }
    }

    public static File collect(Transfers transfers, final File srcDir, @NonNull Base owner) throws PtaiClientException {
        try {
            File destFile = File.createTempFile("PTAI_", ".zip");
            return collect(transfers, srcDir, destFile, owner);
        } catch (IOException e) {
            if (null != owner)
                owner.log(e);
            throw new PtaiClientException(e.getMessage(), e);
        }
    }

    public static File collect(Transfers transfers, final File srcDir, final File destFile, @NonNull Base owner) throws PtaiClientException {
        try {
            if (owner.isVerbose())
                owner.log("Create file collector");
            FileCollector collector = new FileCollector(transfers, owner);

            if ((null == srcDir) || !srcDir.exists() || !srcDir.canRead()) {
                String reason = "Unknown";
                if (null == srcDir)
                    reason = "Null value passed";
                else if (!srcDir.exists())
                    reason = srcDir.getAbsolutePath() + " does not exist";
                else if (!srcDir.canRead())
                    reason = srcDir.getAbsolutePath() + " can not be read";
                throw new PtaiClientException("Invalid source folder, " + reason);
            } else
                owner.log("Folder to collect files from is %s", srcDir.getAbsolutePath());
            owner.log("Sources will be zipped to %s", destFile.getAbsolutePath());
            List<FileCollector.FileEntry> fileEntries = collector.collectFiles(srcDir);
            collector.packCollectedFiles(destFile, fileEntries);
            return destFile;
        } catch (IOException | ArchiveException e) {
            if (null != owner)
                owner.log(e);
            throw new PtaiClientException(e.getMessage(), e);
        }
    }

    protected static final int MAX_DETAILS = 20;
    protected void verboseCollectionDetails(String items[], String prefix) {
        if (null != owner && owner.isVerbose()) {
            if (null == items || 0 == items.length)
                owner.log("=== %s list is empty ===", prefix);
            else {
                owner.log("=== %s [%d] list begin ===", prefix, items.length);
                int total = items.length < MAX_DETAILS ? items.length : MAX_DETAILS;
                int pre = total >> 1;
                int post = total - pre;
                for (int i = 0 ; i < pre ; i++)
                    owner.log("%d: %s", i, items[i]);
                if (items.length != pre + post)
                    owner.log("... Skipping %d entries ...", items.length - pre - post);
                for (int i = items.length - post ; i < items.length ; i++)
                    owner.log("%d: %s", i, items[i]);
                owner.log("==== %s [%d] list end ====", prefix, items.length);
            }
        }
    }

    protected void verbose(String format, Object ... data) {
        if (null != owner && owner.isVerbose())
            owner.log(format, data);
    }

    public List<FileEntry> collectFiles(@NonNull final File source) throws PtaiClientException {
        verbose("collectFiles called for %s", source.getAbsolutePath());
        List<FileEntry> res = new ArrayList<>();
        for (Transfer transfer : this.transfers) {
            // Normalize prefix
            String removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(transfer.getRemovePrefix() + "/")))
                    .orElse("");
            if ('/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);
            verbose("Pattern separator = %s", transfer.getPatternSeparator().isEmpty() ? "[empty]" : transfer.getPatternSeparator());
            verbose("Remove prefix = %s", removePrefix.isEmpty() ? "[empty]" : removePrefix);
            verbose("Includes = %s", transfer.getIncludes().isEmpty() ? "[empty]" : transfer.getIncludes());
            verbose("Use default excludes = %s", transfer.isUseDefaultExcludes());

            final FileSet fileSet = new FileSet();
            if (source.isDirectory())
                fileSet.setDir(source);
            else
                fileSet.setFile(source);
            fileSet.setProject(new Project());
            if (null != transfer.getIncludes())
                for (String pattern : transfer.getIncludes().split(transfer.getPatternSeparator())) {
                    fileSet.createInclude().setName(pattern);
                    verbose("Include pattern = %s", pattern);
                }
            verbose("Excludes = %s", transfer.getExcludes().isEmpty() ? "[empty]" : transfer.getExcludes());
            if (null != transfer.getExcludes())
                for (String pattern : transfer.getExcludes().split(transfer.getPatternSeparator())) {
                    fileSet.createExclude().setName(pattern);
                    verbose("Exclude pattern = %s", pattern);
                }
            fileSet.setDefaultexcludes(transfer.isUseDefaultExcludes());
            String[] files = fileSet.getDirectoryScanner().getIncludedFiles();
            verboseCollectionDetails(files, "Included files");
            verboseCollectionDetails(getScannedDirs(fileSet.getDirectoryScanner()), "Scanned dirs");
            verboseCollectionDetails(fileSet.getDirectoryScanner().getNotIncludedFiles(), "Not included files");
            verboseCollectionDetails(fileSet.getDirectoryScanner().getDeselectedFiles(), "Deselected files");
            verboseCollectionDetails(fileSet.getDirectoryScanner().getExcludedFiles(), "Excluded files");
            // files is an array of this.srcDir - relative paths to files
            Path parentFolder = source.isDirectory() ? source.toPath() : source.getParentFile().toPath();
            for (String file : files) {
                // Normalize relative path
                Path filePath = parentFolder.resolve(file);
                String relativePath = filePath.toUri().normalize().getPath();
                relativePath = StringUtils.removeStart(relativePath, parentFolder.toUri().normalize().getPath());
                String entryName;
                if (transfer.isFlatten())
                    entryName = filePath.getFileName().toString();
                else {
                    if (!relativePath.startsWith(removePrefix))
                        throw new PtaiClientException(String.format("Failed to remove prefix from file named %s. Prefix %s must be present in all file paths", file, removePrefix));
                    entryName = StringUtils.removeStart(relativePath, removePrefix);
                }
                verbose("File %s will be added as %s", filePath.toString(), entryName);
                res.add(new FileEntry(filePath.toString(), entryName));
            }
        }
        return res;
    }

    /*
    There's no need to create multipart Zip-archive during this stage as technically such an archive
    is a single-part archive splitted after creation. That may be checked by opening zip parts starting
    from 2: those files does not contain any headers.
    So if multipart file upload will be implemented, than it is easier to create single-part archive
    and "split" it immediately during upload
    This also means that there's no need to use Zip4J library: it does support multipart archives
    but doesn't allow us to use custom file names as custom file name may be passed only by
    ZipParameter.setFileNameInZip, but there's no way to pass array of ZipParameters into createSplitZipFile
    method.
     */
    public void packCollectedFiles(@NonNull final File destFile, final List<FileEntry> files) throws IOException, ArchiveException {
        verbose("Pack collected files to %s", destFile.getAbsolutePath());
        File destDir = destFile.getParentFile();

        if (!destDir.exists()) {
            verbose("Destination folder %s doesn't exist, creating", destDir.getAbsolutePath());
            destDir.mkdirs();
        }
        OutputStream zipFileStream = new FileOutputStream(destFile);
        ArchiveOutputStream archiveStream;
        archiveStream = new ArchiveStreamFactory().createArchiveOutputStream(ArchiveStreamFactory.ZIP, zipFileStream);
        verbose("Zip stream created");

        for (FileEntry fileEntry : files) {
            verbose("Add %s file as %s to zip stream", fileEntry.fileName, fileEntry.entryName);
            archiveStream.putArchiveEntry(new ZipArchiveEntry(fileEntry.entryName));

            BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileEntry.fileName));
            int size = IOUtils.copy(inputStream, archiveStream);
            verbose("%s zipped", bytesToString(size));
            inputStream.close();
            archiveStream.closeArchiveEntry();
            verbose("File %s added as %s", fileEntry.fileName, fileEntry.entryName);
        }
        verbose("Closing zip stream");
        archiveStream.finish();
        zipFileStream.close();
    }

    private static final double LOG1024 = Math.log10(1024);

    public static String bytesToString(long byteCount) {
        String[] suf = new String[]{ "B", "KB", "MB", "GB", "TB", "PB", "EB" }; // Longs run out around EB
        if (0 == byteCount) return "0 " + suf[0];
        long bytes = Math.abs(byteCount);
        int idx = (int)(Math.floor(Math.log10(bytes) / LOG1024));
        double num = bytes / Math.pow(1024, idx);
        return (byteCount < 0 ? "-" : "") + new DecimalFormat("#.##").format(num) + " " + suf[idx];
    }
}
