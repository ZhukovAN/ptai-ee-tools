package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiTransfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.rest.Upload;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.rest.UploadControllerApi;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import jenkins.MasterToSlaveFileCallable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveOutputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tools.ant.DirectoryScanner;
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
    private final boolean doZip;

    private final String sastConfigUrlPtai;

    public String invoke(final File dir, final VirtualChannel virtualChannel) throws IOException, InterruptedException {
        List<FileEntry> l_objFileEntries = this.collectFiles(dir);
        try {
            String l_strPackedFile = this.packCollectedFiles(dir, l_objFileEntries);

            return this.uploadPackedFile(l_strPackedFile);
        } catch (ArchiveException e) {
            throw new IOException(e.getLocalizedMessage());
        }
    }

    public List<FileEntry> collectFiles(final File dir) {
        List<FileEntry> l_objRes = new ArrayList<FileEntry>();
        for (PtaiTransfer transfer : this.transfers) {
            // Normalize prefix
            String removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(transfer.getRemovePrefix() + "/")))
                    .orElse("");
            if ('/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);

            final FileSet l_objFileSet = new FileSet();
            l_objFileSet.setDir(dir);
            l_objFileSet.setProject(new Project());
            if (null != transfer.getIncludes())
                for (String l_strPattern : transfer.getIncludes().split(transfer.getPatternSeparator()))
                    l_objFileSet.createInclude().setName(l_strPattern);
            if (null != transfer.getExcludes())
                for (String l_strPattern : transfer.getExcludes().split(transfer.getPatternSeparator()))
                    l_objFileSet.createExclude().setName(l_strPattern);
            l_objFileSet.setDefaultexcludes(transfer.isUseDefaultExcludes());
            String[] l_strFiles = l_objFileSet.getDirectoryScanner().getIncludedFiles();
            // l_strFiles is an array of this.dir - relative paths to files
            for (String l_strFile : l_strFiles) {
                // Normalize relative path
                String l_strPathToFile = dir.getAbsolutePath() + File.separator + l_strFile;
                String l_strNormalizedPathToFile = new File(l_strPathToFile).toURI().normalize().getPath();
                String l_strRelativePath = l_strNormalizedPathToFile.replace(dir.toURI().normalize().getPath(), "");
                String l_strEntryName;
                if (transfer.isFlatten())
                    l_strEntryName = new File(l_strPathToFile).getName();
                else {
                    if (!l_strRelativePath.startsWith(removePrefix))
                        throw new PtaiException(Messages.exception_removePrefix_noMatch(l_strFile, removePrefix));
                    l_strEntryName = l_strRelativePath.substring(removePrefix.length());
                }
                l_objRes.add(new FileEntry(l_strPathToFile, l_strEntryName));
            }
        }
        return l_objRes;
    }

    public String packCollectedFiles(final File dir, final List<FileEntry> files) throws IOException, ArchiveException {
        String l_strPackedFileName = UUID.randomUUID().toString();
        String l_strStreamType = ArchiveStreamFactory.TAR;
        if (this.doZip) {
            l_strPackedFileName += ".zip";
            l_strStreamType = ArchiveStreamFactory.ZIP;
        } else
            l_strPackedFileName += ".tar";

        OutputStream l_objArchiveStream = new FileOutputStream(dir.getCanonicalPath() + File.separator + l_strPackedFileName);
        ArchiveOutputStream l_objArchive;
        l_objArchive = new ArchiveStreamFactory().createArchiveOutputStream(l_strStreamType, l_objArchiveStream);

        for (FileEntry l_objFileEntry : files) {
            File l_objFile = new File(l_objFileEntry.fileName);
            ArchiveEntry l_objEntry;
            if (!this.doZip) {
                l_objEntry = new TarArchiveEntry(l_objFileEntry.entryName);
                ((TarArchiveEntry) l_objEntry).setSize(l_objFile.length());
            } else
                l_objEntry = new ZipArchiveEntry(l_objFileEntry.entryName);
            l_objArchive.putArchiveEntry(l_objEntry);
            this.listener.getLogger().printf("%sAdded %s as %s\r\n", Messages.console_message_prefix(), l_objFileEntry.fileName, l_objFileEntry.entryName);

            BufferedInputStream l_objInput = new BufferedInputStream(new FileInputStream(l_objFile));
            IOUtils.copy(l_objInput, l_objArchive);
            l_objInput.close();
            l_objArchive.closeArchiveEntry();
        }
        l_objArchive.finish();
        l_objArchiveStream.close();
        return dir.getCanonicalPath() + File.separator + l_strPackedFileName;
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
