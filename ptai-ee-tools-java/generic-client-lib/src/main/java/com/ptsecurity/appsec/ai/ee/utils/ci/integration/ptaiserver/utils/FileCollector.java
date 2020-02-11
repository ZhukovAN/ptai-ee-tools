package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.FileSet;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class FileCollector {
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

    public static File collect(Transfers transfers, final File srcDir, Base owner) throws PtaiClientException {
        try {
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
            } else {
                if (null != owner)
                    owner.log("Sources to be packed are in ", srcDir.getAbsolutePath());
            }
            File destFile = File.createTempFile("PTAI_", ".zip");
            if (null != owner)
                owner.log("Zipped sources are in  %s\r\n", destFile.getAbsolutePath());

            List<FileCollector.FileEntry> fileEntries = collector.collectFiles(srcDir);
            collector.packCollectedFiles(destFile, fileEntries);
            return destFile;
        } catch (IOException | ArchiveException e) {
            if (null != owner)
                owner.log(e);
            throw new PtaiClientException(e.getMessage(), e);
        }

    }

    public List<FileEntry> collectFiles(final File srcDir) throws PtaiClientException {
        List<FileEntry> res = new ArrayList<>();
        for (Transfer transfer : this.transfers) {
            // Normalize prefix
            String removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(transfer.getRemovePrefix() + "/")))
                    .orElse("");
            if ('/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);

            final FileSet fileSet = new FileSet();
            fileSet.setDir(srcDir);
            fileSet.setProject(new Project());
            if (null != transfer.getIncludes())
                for (String pattern : transfer.getIncludes().split(transfer.getPatternSeparator()))
                    fileSet.createInclude().setName(pattern);
            if (null != transfer.getExcludes())
                for (String pattern : transfer.getExcludes().split(transfer.getPatternSeparator()))
                    fileSet.createExclude().setName(pattern);
            fileSet.setDefaultexcludes(transfer.isUseDefaultExcludes());
            String[] files = fileSet.getDirectoryScanner().getIncludedFiles();
            // files is an array of this.srcDir - relative paths to files
            for (String file : files) {
                // Normalize relative path
                String filePath = srcDir.getAbsolutePath() + File.separator + file;
                String normalizedFilePath = new File(filePath).toURI().normalize().getPath();
                String relativeFilePath = normalizedFilePath.replace(srcDir.toURI().normalize().getPath(), "");
                String entryName;
                if (transfer.isFlatten())
                    entryName = new File(filePath).getName();
                else {
                    if (!relativeFilePath.startsWith(removePrefix))
                        throw new PtaiClientException(String.format("Failed to remove prefix from file named %s. Prefix %s must be present in all file paths", file, removePrefix));
                    entryName = relativeFilePath.substring(removePrefix.length());
                }
                // res.add(new FileEntry(filePath, "SCAN" + "/" + entryName));
                res.add(new FileEntry(filePath, entryName));
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
    public void packCollectedFiles(final File destFile, final List<FileEntry> files) throws IOException, ArchiveException {
        File destDir = destFile.getParentFile();
        if (!destDir.exists())
            destDir.mkdirs();
        OutputStream zipFileStream = new FileOutputStream(destFile);
        ArchiveOutputStream archiveStream;
        archiveStream = new ArchiveStreamFactory().createArchiveOutputStream(ArchiveStreamFactory.ZIP, zipFileStream);

        for (FileEntry fileEntry : files) {
            archiveStream.putArchiveEntry(new ZipArchiveEntry(fileEntry.entryName));

            BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileEntry.fileName));
            IOUtils.copy(inputStream, archiveStream);
            inputStream.close();
            archiveStream.closeArchiveEntry();
            if ((null != owner) && owner.isVerbose())
                owner.log("File %s added as %s\r\n", fileEntry.fileName, fileEntry.entryName);
        }
        archiveStream.finish();
        zipFileStream.close();
    }
}
