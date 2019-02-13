package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiTransfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import hudson.Util;
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

    private final BuildInfo buildInfo;

    private final boolean verbose;

    public String invoke(final File dir, final VirtualChannel virtualChannel) throws IOException, InterruptedException {
        List<FileEntry> l_objFileEntries = this.collectFiles(dir);
        try {
            return this.packCollectedFiles(dir, l_objFileEntries);
        } catch (ArchiveException e) {
            throw new IOException(e.getLocalizedMessage());
        }
    }

    public List<FileEntry> collectFiles(final File dir) {
        List<FileEntry> res = new ArrayList<>();
        for (PtaiTransfer transfer : this.transfers) {
            String removePrefix = Util.replaceMacro(transfer.getRemovePrefix(), buildInfo.getEnvVars());
            String includes = Util.replaceMacro(transfer.getIncludes(), buildInfo.getEnvVars());
            String excludes = Util.replaceMacro(transfer.getExcludes(), buildInfo.getEnvVars());
            // Normalize prefix
            removePrefix = Optional.ofNullable(
                    FilenameUtils.separatorsToUnix(
                            FilenameUtils.normalize(removePrefix + "/")))
                    .orElse("");
            if ('/' == removePrefix.charAt(0))
                removePrefix = removePrefix.substring(1);

            final FileSet fileSet = new FileSet();
            fileSet.setDir(dir);
            fileSet.setProject(new Project());
            if (null != includes)
                for (String pattern : includes.split(transfer.getPatternSeparator()))
                    fileSet.createInclude().setName(pattern);
            if (null != excludes)
                for (String pattern : excludes.split(transfer.getPatternSeparator()))
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
            if (verbose)
                this.listener.getLogger().printf("%s%s\r\n", Messages.console_message_prefix(), Messages.plugin_logFileAddedToZip(fileEntry.fileName, fileEntry.entryName));
        }
        archiveStream.finish();
        zipFileStream.close();
        return dir.getCanonicalPath() + File.separator + zipFileName;
    }
}
