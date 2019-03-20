package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
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
import java.util.UUID;

@RequiredArgsConstructor
public class FileCollector {
    @AllArgsConstructor
    @Getter
    private final static class FileEntry {
        private final String fileName;
        private final String entryName;
    }

    private final Transfers transfers;
    private final Base owner;

    public void collect(final File srcDir, final File destFile) throws PtaiClientException {
        List<FileEntry> fileEntries = this.collectFiles(srcDir);
        try {
            this.packCollectedFiles(srcDir, destFile, fileEntries);
        } catch (ArchiveException | IOException e) {
            throw new PtaiClientException("File collect error", e);
        }
    }

    protected List<FileEntry> collectFiles(final File srcDir) throws PtaiClientException {
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
                res.add(new FileEntry(filePath, entryName));
            }
        }
        return res;
    }

    protected void packCollectedFiles(final File srcDir, final File destFile, final List<FileEntry> files) throws IOException, ArchiveException {
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
