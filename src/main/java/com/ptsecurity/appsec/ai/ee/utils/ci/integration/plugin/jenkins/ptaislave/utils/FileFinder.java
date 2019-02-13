package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import jenkins.MasterToSlaveFileCallable;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.FileSet;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;

public class FileFinder extends MasterToSlaveFileCallable<FileFinderResult> {
    public static final String DEFAULT_PATTERN_SEPARATOR = "[, ]+";

    private final String includes;
    private final String excludes;
    private final boolean defaultExcludes;
    private final boolean findEmptyDirectories;
    private final String patternSeparatorRegex;

    public FileFinder(final String theIncludes, final String theExcludes,
                      final boolean theDefaultExcludes, final boolean theFindEmptyDirectories,
                      final String thePatternSeparatorRegex) {
        this.includes = theIncludes;
        this.excludes = theExcludes;
        this.defaultExcludes = theDefaultExcludes;
        this.findEmptyDirectories = theFindEmptyDirectories;
        this.patternSeparatorRegex = thePatternSeparatorRegex == null ? DEFAULT_PATTERN_SEPARATOR
                : thePatternSeparatorRegex;
    }

    public FileFinderResult invoke(final File file, final VirtualChannel virtualChannel) throws IOException {
        final DirectoryScanner scanner = createDirectoryScanner(file, includes, excludes, defaultExcludes, patternSeparatorRegex);
        final String[] includedFiles = scanner.getIncludedFiles();
        final FilePath[] files = toFilePathArray(file, includedFiles);
        FilePath[] dirs = new FilePath[0];
        if (findEmptyDirectories) {
            final String[] allDirs = scanner.getIncludedDirectories();
            final String[] onlyLeaf = reduce(allDirs, allDirs);
            dirs = toFilePathArray(file, reduce(onlyLeaf, includedFiles));
        }
        return new FileFinderResult(files, dirs);
    }

    private static DirectoryScanner createDirectoryScanner(final File dir, final String includes, final String excludes,
                                                   final boolean defaultExcludes, final String patternSeparatorRegex) throws IOException {
        final FileSet fs = new FileSet();
        fs.setDir(dir);
        fs.setProject(new Project());
        if (includes != null) {
            final String[] includePatterns = includes.split(patternSeparatorRegex);
            for (String pattern : includePatterns)
                if (!"".equals(pattern))
                    fs.createInclude().setName(pattern);
        }
        if (excludes != null) {
            final String[] excludePatterns = excludes.split(patternSeparatorRegex);
            for (String pattern : excludePatterns)
                if (!"".equals(pattern))
                    fs.createExclude().setName(pattern);
        }
        fs.setDefaultexcludes(defaultExcludes);
        return fs.getDirectoryScanner();
    }

    static String[] reduce(final String[] directories, final String[] paths) {
        final HashSet<String> result = new HashSet(Arrays.asList(directories));
        final LinkedHashSet<String> pathSet = new LinkedHashSet(Arrays.asList(paths));
        result.remove("");
        pathSet.remove("");
        for (final String dir : directories)
            for (final String potential : pathSet)
                if (potential.startsWith(dir + File.separator)) {
                    result.remove(dir);
                    pathSet.remove(dir);
                    break;
                }
        return result.toArray(new String[result.size()]);
    }

    private static FilePath[] toFilePathArray(final File file, final String[] includedFiles) {
        final FilePath[] filePaths = new FilePath[includedFiles.length];
        for (int i = 0; i < filePaths.length; i++)
            filePaths[i] = new FilePath(new File(file, includedFiles[i]));
        return filePaths;
    }
}
