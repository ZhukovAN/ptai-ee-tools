package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiTransfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import jenkins.MasterToSlaveFileCallable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.FileSet;

import java.io.*;
import java.util.*;

@AllArgsConstructor
public class FileUploader extends MasterToSlaveFileCallable<String> {
    @AllArgsConstructor
    @Getter
    private final static class FileEntry {
        private final String fileName;
        private final String entryName;
    }

    private final TaskListener listener;

    private final List<PtaiTransfer> transfers;

    private final String sastConfigUrlPtai;

    public String invoke(final File dir, final VirtualChannel virtualChannel) throws IOException, InterruptedException {
        List<FileEntry> l_objFileEntries = this.collectFiles(dir);
        try {
            return this.packCollectedFiles(dir, l_objFileEntries);
        } catch (ArchiveException e) {
            throw new IOException(e.getLocalizedMessage());
        }
    }

    public List<FileEntry> collectFiles(final File dir) {
        List<FileEntry> res = new ArrayList<FileEntry>();
        for (PtaiTransfer transfer : this.transfers) {
            // Normalize prefix
            String removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(transfer.getRemovePrefix() + "/")))
                    .orElse("");
            if ('/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);

            final FileSet fileSet = new FileSet();
            fileSet.setDir(dir);
            fileSet.setProject(new Project());
            if (null != transfer.getIncludes())
                for (String pattern : transfer.getIncludes().split(transfer.getPatternSeparator()))
                    fileSet.createInclude().setName(pattern);
            if (null != transfer.getExcludes())
                for (String pattern : transfer.getExcludes().split(transfer.getPatternSeparator()))
                    fileSet.createExclude().setName(pattern);
            fileSet.setDefaultexcludes(transfer.isUseDefaultExcludes());
            String[] files = fileSet.getDirectoryScanner().getIncludedFiles();
            // files is an array of this.dir - relative paths to files
            for (String file : files) {
                // Normalize relative path
                String filePath = dir.getAbsolutePath() + File.separator + file;
                String normalizedFilePath = new File(filePath).toURI().normalize().getPath();
                String relativeFilePath = normalizedFilePath.replace(dir.toURI().normalize().getPath(), "");
                String entryName;
                if (transfer.isFlatten())
                    entryName = new File(filePath).getName();
                else {
                    if (!relativeFilePath.startsWith(removePrefix))
                        throw new PtaiException(Messages.exception_removePrefix_noMatch(file, removePrefix));
                    entryName = relativeFilePath.substring(removePrefix.length());
                }
                res.add(new FileEntry(filePath, entryName));
            }
        }
        return res;
    }

    public String packCollectedFiles(final File dir, final List<FileEntry> files) throws IOException, ArchiveException {
        String zipFileName = UUID.randomUUID().toString() + ".zip";

        OutputStream zipFileStream = new FileOutputStream(dir.getCanonicalPath() + File.separator + zipFileName);
        ArchiveOutputStream archiveStream;
        archiveStream = new ArchiveStreamFactory().createArchiveOutputStream(ArchiveStreamFactory.ZIP, zipFileStream);

        for (FileEntry fileEntry : files) {
            archiveStream.putArchiveEntry(new ZipArchiveEntry(fileEntry.entryName));

            BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(fileEntry.fileName));
            IOUtils.copy(inputStream, archiveStream);
            inputStream.close();
            archiveStream.closeArchiveEntry();
            this.listener.getLogger().printf("%sAdded %s as %s\r\n", Messages.console_message_prefix(), fileEntry.fileName, fileEntry.entryName);
        }
        archiveStream.finish();
        zipFileStream.close();
        return dir.getCanonicalPath() + File.separator + zipFileName;
    }

    public String uploadPackedFile(final String fileName) {
        final int maxPartSize = 1024 * 1024;
        byte[] l_intArray = new byte[maxPartSize];
        try {
            /*
            UploadControllerApi l_objApi = new ApiClient().setBasePath(this.sastConfigUrlPtai).buildClient(UploadControllerApi.class);
            Upload l_objId = l_objApi.beginUploadUsingPOST();

            RandomAccessFile l_objSrcFile = new RandomAccessFile(fileName,"r");

            long l_intSize = l_objSrcFile.length();
            long l_intChunks = (long) Math.ceil((double) l_intSize / (double) maxPartSize);
            int l_intDigits = 1 + (int)(Math.log10(l_intChunks));
            final String l_strFmt = "%s.part.%0" + String.valueOf(l_intDigits) + "d";

            for (long i = 0; i < l_intChunks; i++) {
                String l_strChunkFileName = String.format(l_strFmt, fileName, i);

                int l_intBytesRead = l_objSrcFile.read(l_intArray);
                if (-1 == l_intBytesRead) break;

                try (FileOutputStream fos = new FileOutputStream(l_strChunkFileName)) {
                    fos.write(l_intArray, 0, l_intBytesRead);
                }
                File l_objFileToTransfer = new File(l_strChunkFileName);
                l_objApi.fileUploadUsingPOST(l_objFileToTransfer, l_objId.getId());
                l_objFileToTransfer.delete();
            }
            l_objSrcFile.close();
            new File(fileName).delete();
            l_objApi.endUploadUsingPOST(l_objId.getId());
            return l_objId.getId();
            */
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
