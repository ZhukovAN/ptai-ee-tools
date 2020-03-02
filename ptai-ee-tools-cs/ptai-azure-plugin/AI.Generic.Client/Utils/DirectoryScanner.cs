using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AI.Generic.Client.Utils {
    public class DirectoryScanner {
        /** Is OpenVMS the operating system we're running on? */
        private static readonly bool ON_VMS = false;

        protected static readonly String[] DEFAULTEXCLUDES = { 
            // Miscellaneous typical temporary files
            SelectorUtils.DEEP_TREE_MATCH + "/*~",
            SelectorUtils.DEEP_TREE_MATCH + "/#*#",
            SelectorUtils.DEEP_TREE_MATCH + "/.#*",
            SelectorUtils.DEEP_TREE_MATCH + "/%*%",
            SelectorUtils.DEEP_TREE_MATCH + "/._*",

            // CVS
            SelectorUtils.DEEP_TREE_MATCH + "/CVS",
            SelectorUtils.DEEP_TREE_MATCH + "/CVS/" + SelectorUtils.DEEP_TREE_MATCH,
            SelectorUtils.DEEP_TREE_MATCH + "/.cvsignore",

            // SCCS
            SelectorUtils.DEEP_TREE_MATCH + "/SCCS",
            SelectorUtils.DEEP_TREE_MATCH + "/SCCS/" + SelectorUtils.DEEP_TREE_MATCH,

            // Visual SourceSafe
            SelectorUtils.DEEP_TREE_MATCH + "/vssver.scc",

            // Subversion
            SelectorUtils.DEEP_TREE_MATCH + "/.svn",
            SelectorUtils.DEEP_TREE_MATCH + "/.svn/" + SelectorUtils.DEEP_TREE_MATCH,

            // Git
            SelectorUtils.DEEP_TREE_MATCH + "/.git",
            SelectorUtils.DEEP_TREE_MATCH + "/.git/" + SelectorUtils.DEEP_TREE_MATCH,
            SelectorUtils.DEEP_TREE_MATCH + "/.gitattributes",
            SelectorUtils.DEEP_TREE_MATCH + "/.gitignore",
            SelectorUtils.DEEP_TREE_MATCH + "/.gitmodules",

            // Mercurial
            SelectorUtils.DEEP_TREE_MATCH + "/.hg",
            SelectorUtils.DEEP_TREE_MATCH + "/.hg/" + SelectorUtils.DEEP_TREE_MATCH,
            SelectorUtils.DEEP_TREE_MATCH + "/.hgignore",
            SelectorUtils.DEEP_TREE_MATCH + "/.hgsub",
            SelectorUtils.DEEP_TREE_MATCH + "/.hgsubstate",
            SelectorUtils.DEEP_TREE_MATCH + "/.hgtags",

            // Bazaar
            SelectorUtils.DEEP_TREE_MATCH + "/.bzr",
            SelectorUtils.DEEP_TREE_MATCH + "/.bzr/" + SelectorUtils.DEEP_TREE_MATCH,
            SelectorUtils.DEEP_TREE_MATCH + "/.bzrignore",

            // Mac
            SelectorUtils.DEEP_TREE_MATCH + "/.DS_Store"
        };

        /**
         * default value for {@link #maxLevelsOfSymlinks maxLevelsOfSymlinks}
         * @since Ant 1.8.0
         */
        public static readonly int MAX_LEVELS_OF_SYMLINKS = 5;
        /**
         * The end of the exception message if something that should be
         * there doesn't exist.
         */
        public static readonly String DOES_NOT_EXIST_POSTFIX = " does not exist.";

        /** Helper. */
        private static readonly FileUtils FILE_UTILS = FileUtils.getFileUtils();

        /**
         * Patterns which should be excluded by default.
         *
         * @see #addDefaultExcludes()
         */
        private static readonly HashSet<String> defaultExcludes = new HashSet<String>();
        static DirectoryScanner() {
            resetDefaultExcludes();
        }

        /** The base directory to be scanned. */
        protected FileInfo basedir { get; set; }

        /** The patterns for the files to be included. */
        protected String[] includes;

        /** The patterns for the files to be excluded. */
        protected String[] excludes;

        /** Selectors that will filter which files are in our candidate list. */
        protected FileSelector[] selectors { get; set; } = null;

        /**
         * The files which matched at least one include and no excludes
         * and were selected.
         */
        protected List<String> filesIncluded;

        /** The files which did not match any includes or selectors. */
        protected List<String> filesNotIncluded;

        /**
         * The files which matched at least one include and at least
         * one exclude.
         */
        protected List<String> filesExcluded;

        /**
         * The directories which matched at least one include and no excludes
         * and were selected.
         */
        protected List<String> dirsIncluded;

        /** The directories which were found and did not match any includes. */
        protected List<String> dirsNotIncluded;

        /**
         * The directories which matched at least one include and at least one
         * exclude.
         */
        protected List<String> dirsExcluded;

        /**
         * The files which matched at least one include and no excludes and
         * which a selector discarded.
         */
        protected List<String> filesDeselected;

        /**
         * The directories which matched at least one include and no excludes
         * but which a selector discarded.
         */
        protected List<String> dirsDeselected;

        /** Whether or not our results were built by a slow scan. */
        protected bool haveSlowResults = false;

        /**
         * Whether or not the file system should be treated as a case sensitive
         * one.
         */
        protected bool isCaseSensitive { get; set; } = true;

        /**
         * Whether a missing base directory is an error.
         * @since Ant 1.7.1
         */
        protected bool errorOnMissingDir { get; set; } = true;

        /**
         * Whether or not symbolic links should be followed.
         *
         * @since Ant 1.5
         */
        private bool followSymlinks { get; set; } = true;

        /** Whether or not everything tested so far has been included. */
        protected bool everythingIncluded { get; set; } = true;

        // CheckStyle:VisibilityModifier ON

        /**
         * List of all scanned directories.
         *
         * @since Ant 1.6
         */
        private HashSet<String> scannedDirs { get; } = new HashSet<String>();

        /**
         * Map of all include patterns that are full file names and don't
         * contain any wildcards.
         *
         * <p>Maps pattern string to TokenizedPath.</p>
         *
         * <p>If this instance is not case sensitive, the file names get
         * turned to upper case.</p>
         *
         * <p>Gets lazily initialized on the first invocation of
         * isIncluded or isExcluded and cleared at the end of the scan
         * method (cleared in clearCaches, actually).</p>
         *
         * @since Ant 1.8.0
         */
        private readonly Dictionary<String, TokenizedPath> includeNonPatterns = new Dictionary<String, TokenizedPath>();

        /**
         * Map of all exclude patterns that are full file names and don't
         * contain any wildcards.
         *
         * <p>Maps pattern string to TokenizedPath.</p>
         *
         * <p>If this instance is not case sensitive, the file names get
         * turned to upper case.</p>
         *
         * <p>Gets lazily initialized on the first invocation of
         * isIncluded or isExcluded and cleared at the end of the scan
         * method (cleared in clearCaches, actually).</p>
         *
         * @since Ant 1.8.0
         */
        private readonly Dictionary<String, TokenizedPath> excludeNonPatterns = new Dictionary<String, TokenizedPath>();

        /**
         * Array of all include patterns that contain wildcards.
         *
         * <p>Gets lazily initialized on the first invocation of
         * isIncluded or isExcluded and cleared at the end of the scan
         * method (cleared in clearCaches, actually).</p>
         */
        private TokenizedPattern[] includePatterns;

        /**
         * Array of all exclude patterns that contain wildcards.
         *
         * <p>Gets lazily initialized on the first invocation of
         * isIncluded or isExcluded and cleared at the end of the scan
         * method (cleared in clearCaches, actually).</p>
         */
        private TokenizedPattern[] excludePatterns;

        /**
         * Have the non-pattern sets and pattern arrays for in- and
         * excludes been initialized?
         *
         * @since Ant 1.6.3
         */
        private bool areNonPatternSetsReady = false;

        /**
         * Scanning flag.
         *
         * @since Ant 1.6.3
         */
        private bool scanning = false;

        /**
         * Scanning lock.
         *
         * @since Ant 1.6.3
         */
        private readonly Object scanLock = new Object();

        /**
         * Slow scanning flag.
         *
         * @since Ant 1.6.3
         */
        private bool slowScanning = false;

        /**
         * Slow scanning lock.
         *
         * @since Ant 1.6.3
         */
        private readonly Object slowScanLock = new Object();

        /**
         * Exception thrown during scan.
         *
         * @since Ant 1.6.3
         */
        private Exception illegal = null;

        /**
         * The maximum number of times a symbolic link may be followed
         * during a scan.
         *
         * @since Ant 1.8.0
         */
        private int maxLevelsOfSymlinks { get; set; } = MAX_LEVELS_OF_SYMLINKS;


        /**
         * Absolute paths of all symlinks that haven't been followed but
         * would have been if followsymlinks had been true or
         * maxLevelsOfSymlinks had been higher.
         *
         * @since Ant 1.8.0
         */
        private readonly HashSet<String> notFollowedSymlinks = new HashSet<String>();

        /**
         * Test whether or not a given path matches the start of a given
         * pattern up to the first "**".
         * <p>
         * This is not a general purpose test and should only be used if you
         * can live with false positives. For example, <code>pattern=**\a</code>
         * and <code>str=b</code> will yield <code>true</code>.
         *
         * @param pattern The pattern to match against. Must not be
         *                <code>null</code>.
         * @param str     The path to match, as a String. Must not be
         *                <code>null</code>.
         *
         * @return whether or not a given path matches the start of a given
         * pattern up to the first "**".
         */
        protected static bool matchPatternStart(String pattern, String str) {
            return SelectorUtils.matchPatternStart(pattern, str);
        }

        /**
         * Test whether or not a given path matches the start of a given
         * pattern up to the first "**".
         * <p>
         * This is not a general purpose test and should only be used if you
         * can live with false positives. For example, <code>pattern=**\a</code>
         * and <code>str=b</code> will yield <code>true</code>.
         *
         * @param pattern The pattern to match against. Must not be
         *                <code>null</code>.
         * @param str     The path to match, as a String. Must not be
         *                <code>null</code>.
         * @param isCaseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         * @return whether or not a given path matches the start of a given
         * pattern up to the first "**".
         */
        protected static bool matchPatternStart(String pattern, String str, bool isCaseSensitive) {
            return SelectorUtils.matchPatternStart(pattern, str, isCaseSensitive);
        }

        /**
         * Test whether or not a given path matches a given pattern.
         *
         * @param pattern The pattern to match against. Must not be
         *                <code>null</code>.
         * @param str     The path to match, as a String. Must not be
         *                <code>null</code>.
         *
         * @return <code>true</code> if the pattern matches against the string,
         *         or <code>false</code> otherwise.
         */
        protected static bool matchPath(String pattern, String str) {
            return SelectorUtils.matchPath(pattern, str);
        }

        /**
         * Test whether or not a given path matches a given pattern.
         *
         * @param pattern The pattern to match against. Must not be
         *                <code>null</code>.
         * @param str     The path to match, as a String. Must not be
         *                <code>null</code>.
         * @param isCaseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         * @return <code>true</code> if the pattern matches against the string,
         *         or <code>false</code> otherwise.
         */
        protected static bool matchPath(String pattern, String str, bool isCaseSensitive) {
            return SelectorUtils.matchPath(pattern, str, isCaseSensitive);
        }

        /**
         * Test whether or not a string matches against a pattern.
         * The pattern may contain two special characters:<br>
         * '*' means zero or more characters<br>
         * '?' means one and only one character
         *
         * @param pattern The pattern to match against.
         *                Must not be <code>null</code>.
         * @param str     The string which must be matched against the pattern.
         *                Must not be <code>null</code>.
         *
         * @return <code>true</code> if the string matches against the pattern,
         *         or <code>false</code> otherwise.
         */
        public static bool match(String pattern, String str) {
            return SelectorUtils.match(pattern, str);
        }

        /**
         * Test whether or not a string matches against a pattern.
         * The pattern may contain two special characters:<br>
         * '*' means zero or more characters<br>
         * '?' means one and only one character
         *
         * @param pattern The pattern to match against.
         *                Must not be <code>null</code>.
         * @param str     The string which must be matched against the pattern.
         *                Must not be <code>null</code>.
         * @param isCaseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         *
         * @return <code>true</code> if the string matches against the pattern,
         *         or <code>false</code> otherwise.
         */
        protected static bool match(String pattern, String str, bool isCaseSensitive) {
            return SelectorUtils.match(pattern, str, isCaseSensitive);
        }


        /**
         * Get the list of patterns that should be excluded by default.
         *
         * @return An array of <code>String</code> based on the current
         *         contents of the <code>defaultExcludes</code>
         *         <code>Set</code>.
         *
         * @since Ant 1.6
         */
        public static String[] getDefaultExcludes() {
            return defaultExcludes.ToArray();
        }

        /**
         * Add a pattern to the default excludes unless it is already a
         * default exclude.
         *
         * @param s   A string to add as an exclude pattern.
         * @return    <code>true</code> if the string was added;
         *            <code>false</code> if it already existed.
         *
         * @since Ant 1.6
         */
        public static bool addDefaultExclude(String s) {
            return defaultExcludes.Add(s);
        }

        /**
         * Remove a string if it is a default exclude.
         *
         * @param s   The string to attempt to remove.
         * @return    <code>true</code> if <code>s</code> was a default
         *            exclude (and thus was removed);
         *            <code>false</code> if <code>s</code> was not
         *            in the default excludes list to begin with.
         *
         * @since Ant 1.6
         */
        public static bool removeDefaultExclude(String s) {
            return defaultExcludes.Remove(s);
        }

        /**
         * Go back to the hardwired default exclude patterns.
         *
         * @since Ant 1.6
         */
        public static void resetDefaultExcludes() {
            defaultExcludes.Clear();
            defaultExcludes.UnionWith(DEFAULTEXCLUDES);
        }

        /**
         * Set the base directory to be scanned. This is the directory which is
         * scanned recursively. All '/' and '\' characters are replaced by
         * <code>Path.DirectorySeparatorChar</code>, so the separator used need not match
         * <code>Path.DirectorySeparatorChar</code>.
         *
         * @param basedir The base directory to scan.
         */
        public void setBasedir(String basedir) {
            this.basedir = basedir == null 
                ? null
                : new FileInfo(basedir.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar));
        }

        /**
         * Set the list of include patterns to use. All '/' and '\' characters
         * are replaced by <code>Path.DirectorySeparatorChar</code>, so the separator used
         * need not match <code>Path.DirectorySeparatorChar</code>.
         * <p>
         * When a pattern ends with a '/' or '\', "**" is appended.
         *
         * @param includes A list of include patterns.
         *                 May be <code>null</code>, indicating that all files
         *                 should be included. If a non-<code>null</code>
         *                 list is given, all elements must be
         *                 non-<code>null</code>.
         */
        public void setIncludes(String[] includes) {
            if (includes == null)
                this.includes = new String[0];
            else
                this.includes = includes.Select(item => DirectoryScanner.normalizePattern(item)).ToArray();
        }

        /**
         * Set the list of exclude patterns to use. All '/' and '\' characters
         * are replaced by <code>Path.DirectorySeparatorChar</code>, so the separator used
         * need not match <code>Path.DirectorySeparatorChar</code>.
         * <p>
         * When a pattern ends with a '/' or '\', "**" is appended.
         *
         * @param excludes A list of exclude patterns.
         *                 May be <code>null</code>, indicating that no files
         *                 should be excluded. If a non-<code>null</code> list is
         *                 given, all elements must be non-<code>null</code>.
         */
        public void setExcludes(String[] excludes) {
            if (excludes == null) 
                this.excludes = new String[0];
            else
                this.excludes = Enumerable.ToArray(excludes.Select(item => DirectoryScanner.normalizePattern(item)));
        }

        /**
         * Add to the list of exclude patterns to use. All '/' and '\'
         * characters are replaced by <code>Path.DirectorySeparatorChar</code>, so
         * the separator used need not match <code>Path.DirectorySeparatorChar</code>.
         * <p>
         * When a pattern ends with a '/' or '\', "**" is appended.
         *
         * @param excludes A list of exclude patterns.
         *                 May be <code>null</code>, in which case the
         *                 exclude patterns don't get changed at all.
         *
         * @since Ant 1.6.3
         */
        public void addExcludes(String[] excludes) {
            if (excludes != null && excludes.Length > 0) {
                if (this.excludes == null || this.excludes.Length == 0) 
                    setExcludes(excludes);
                else
                    this.excludes = Enumerable.ToArray(
                        this.excludes.Concat(excludes.Select(item => DirectoryScanner.normalizePattern(item))));
            }
        }

        /**
         * All '/' and '\' characters are replaced by
         * <code>Path.DirectorySeparatorChar</code>, so the separator used need not
         * match <code>Path.DirectorySeparatorChar</code>.
         *
         * <p>When a pattern ends with a '/' or '\', "**" is appended.</p>
         *
         * @since Ant 1.6.3
         */
        private static String normalizePattern(String p) {
            String pattern = p.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
            if (pattern.EndsWith(Path.DirectorySeparatorChar.ToString()))
                pattern += SelectorUtils.DEEP_TREE_MATCH;
            return pattern;
        }

        /**
         * Scan for files which match at least one include pattern and don't match
         * any exclude patterns. If there are selectors then the files must pass
         * muster there, as well.  Scans under basedir, if set; otherwise the
         * include patterns without leading wildcards specify the absolute paths of
         * the files that may be included.
         *
         * @exception IllegalStateException if the base directory was set
         *            incorrectly (i.e. if it doesn't exist or isn't a directory).
         */
        public void scan() {
            lock (scanLock) {
                if (scanning) {
                    while (scanning) {
                        try {
                            Monitor.Wait(scanLock);
                        } catch (ThreadInterruptedException ignored) {}
                    }
                    if (illegal != null) throw illegal;
                    return;
                }
                scanning = true;
            }
            FileInfo savedBase = basedir;
            try {
                lock(this) {
                    illegal = null;
                    clearResults();

                    // set in/excludes to reasonable defaults if needed:
                    bool nullIncludes = includes == null;
                    includes = nullIncludes ? new String[] { SelectorUtils.DEEP_TREE_MATCH } : includes;
                    bool nullExcludes = excludes == null;
                    excludes = nullExcludes ? new String[0] : excludes;

                    if (basedir != null && !followSymlinks
                        && basedir.Attributes.HasFlag(FileAttributes.ReparsePoint)) {
                        notFollowedSymlinks.Add(basedir.FullName);
                        basedir = null;
                    }

                    if (basedir == null) 
                        // if no basedir and no includes, nothing to do:
                        if (nullIncludes) return;
                    else {
                        if (!basedir.Exists) {
                            if (errorOnMissingDir) 
                                illegal = new Exception("basedir " + basedir + DOES_NOT_EXIST_POSTFIX);
                            else 
                                // Nothing to do - basedir does not exist
                                return;
                        } else if (!basedir.Attributes.HasFlag(FileAttributes.Directory))
                            illegal = new Exception("basedir " + basedir + " is not a directory.");
                        if (illegal != null) throw illegal;
                    }
                    if (isIncluded(TokenizedPath.EMPTY_PATH)) {
                        if (isExcluded(TokenizedPath.EMPTY_PATH)) 
                            dirsExcluded.Add("");
                        else if (isSelected("", basedir)) 
                            dirsIncluded.Add("");
                        else 
                            dirsDeselected.Add("");
                    } else 
                        dirsNotIncluded.Add("");
                    checkIncludePatterns();
                    clearCaches();
                    includes = nullIncludes ? null : includes;
                    excludes = nullExcludes ? null : excludes;
                }
            } finally {
                basedir = savedBase;
                lock(scanLock) {
                    scanning = false;
                    Monitor.PulseAll(scanLock);
                }
            }
        }

        /**
         * This routine is actually checking all the include patterns in
         * order to avoid scanning everything under base dir.
         * @since Ant 1.6
         */
        private void checkIncludePatterns() {
            ensureNonPatternSetsReady();
            Dictionary<TokenizedPath, String> newroots = new Dictionary<TokenizedPath, String>();

            // put in the newroots map the include patterns without
            // wildcard tokens
            foreach (TokenizedPattern includePattern in includePatterns) {
                String pattern = includePattern.toString();
                if (!shouldSkipPattern(pattern)) {
                    newroots.Add(includePattern.rtrimWildcardTokens(), pattern);
                }
            }
            foreach (KeyValuePair<String, TokenizedPath> entry in includeNonPatterns) {
                String pattern = entry.Key;
                if (!shouldSkipPattern(pattern)) {
                    newroots.Add(entry.Value, pattern);
                }
            }

        if (newroots.ContainsKey(TokenizedPath.EMPTY_PATH) && basedir != null)
            // we are going to scan everything anyway
            scandir(basedir, "", true);
        else {
            FileInfo canonBase = null;
            if (basedir != null) 
                canonBase = new FileInfo(basedir.FullName);
            // only scan directories that can include matched files or
            // directories
            foreach (KeyValuePair<TokenizedPath, String> entry in newroots) {
                TokenizedPath currentPath = entry.Key;
                String currentelement = currentPath.ToString();
                if (basedir == null && !FileUtils.isAbsolutePath(currentelement)) continue;
                FileInfo myfile = new FileInfo(Path.Combine(basedir.FullName, currentelement));

                if (myfile.Exists) {
                    // may be on a case insensitive file system.  We want
                    // the results to show what's really on the disk, so
                    // we need to double check.
                    String path = (basedir == null)
                        ? myfile.FullName
                        : FILE_UTILS.removeLeadingPath(canonBase, myfile);
                    if (!path.Equals(currentelement) || ON_VMS) {
                        myfile = currentPath.findFile(basedir, true);
                        if (myfile != null && basedir != null) {
                            currentelement = FILE_UTILS.removeLeadingPath(basedir, myfile);
                            if (!currentPath.ToString().Equals(currentelement))
                                currentPath = new TokenizedPath(currentelement);
                        }
                    }
                }

                if ((myfile == null || !myfile.Exists) && !isCaseSensitive) {
                    FileInfo f = currentPath.findFile(basedir, false);
                    if (f != null && f.Exists) {
                        // adapt currentelement to the case we've
                        // actually found
                        currentelement = (basedir == null)
                            ? f.FullName
                            : FILE_UTILS.removeLeadingPath(basedir, f);
                        myfile = f;
                        currentPath = new TokenizedPath(currentelement);
                    }
                }

                if (myfile != null && myfile.Exists) {
                    if (!followSymlinks && currentPath.isSymlink(basedir)) {
                        accountForNotFollowedSymlink(currentPath, myfile);
                        continue;
                    }
                    if (myfile.Attributes.HasFlag(FileAttributes.Directory)) {
                        if (isIncluded(currentPath) && !currentelement.Equals("")) {
                            accountForIncludedDir(currentPath, myfile, true);
                        } else {
                            scandir(myfile, currentPath, true);
                        }
                    } else if (myfile.Attributes.HasFlag(FileAttributes.Normal)) {
                        String originalpattern = entry.Value;
                        bool included = isCaseSensitive
                            ? originalpattern.Equals(currentelement)
                            : originalpattern.Equals(currentelement, StringComparison.OrdinalIgnoreCase);
                        if (included) 
                            accountForIncludedFile(currentPath, myfile);
                    }
                }
            }
        }
    }

        /**
         * true if the pattern specifies a relative path without basedir
         * or an absolute path not inside basedir.
         *
         * @since Ant 1.8.0
         */
        private bool shouldSkipPattern(String pattern) {
            if (FileUtils.isAbsolutePath(pattern)) {
                //skip abs. paths not under basedir, if set:
                return !(basedir == null || SelectorUtils.matchPatternStart(pattern, basedir.FullName, isCaseSensitive));
            }
            return basedir == null;
        }

        /**
         * Clear the result caches for a scan.
         */
        protected void clearResults() {
            filesIncluded = new List<String>();
            filesNotIncluded = new List<String>();
            filesExcluded = new List<String>();
            filesDeselected = new List<String> ();
            dirsIncluded = new List<String>();
            dirsNotIncluded = new List<String>();
            dirsExcluded = new List<String>();
            dirsDeselected = new List<String>();
            everythingIncluded = (basedir != null);
            scannedDirs.Clear();
            notFollowedSymlinks.Clear();
        }

        /**
         * Top level invocation for a slow scan. A slow scan builds up a full
         * list of excluded/included files/directories, whereas a fast scan
         * will only have full results for included files, as it ignores
         * directories which can't possibly hold any included files/directories.
         * <p>
         * Returns immediately if a slow scan has already been completed.
         */
        protected void slowScan() {
            lock(slowScanLock) {
                if (haveSlowResults) return;
                if (slowScanning) {
                    while (slowScanning) {
                        try {
                            Monitor.Wait(slowScanLock);
                        } catch (ThreadInterruptedException e) {}
                    }
                    return;
                }
                slowScanning = true;
            }
            try {
                lock(this) {

                    // set in/excludes to reasonable defaults if needed:
                    bool nullIncludes = (includes == null);
                    includes = nullIncludes ? new String[] { SelectorUtils.DEEP_TREE_MATCH } : includes;
                    bool nullExcludes = (excludes == null);
                    excludes = nullExcludes ? new String[0] : excludes;

                    String[] excl = dirsExcluded.ToArray();

                    String[] notIncl = dirsNotIncluded.ToArray();

                    ensureNonPatternSetsReady();

                    processSlowScan(excl);
                    processSlowScan(notIncl);
                    clearCaches();
                    includes = nullIncludes ? null : includes;
                    excludes = nullExcludes ? null : excludes;
                }
            } finally {
                lock(slowScanLock) {
                    haveSlowResults = true;
                    slowScanning = false;
                    Monitor.PulseAll(slowScanLock);
                }
            }
        }

        private void processSlowScan(String[] arr) {
            foreach (String element in arr) {
                TokenizedPath path = new TokenizedPath(element);
                if (!couldHoldIncluded(path) || contentsExcluded(path)) {
                    scandir(new FileInfo(Path.Combine(basedir.FullName, element)), path, false);
                }
            }
        }

        /**
         * Scan the given directory for files and directories. Found files and
         * directories are placed in their respective collections, based on the
         * matching of includes, excludes, and the selectors.  When a directory
         * is found, it is scanned recursively.
         *
         * @param dir   The directory to scan. Must not be <code>null</code>.
         * @param vpath The path relative to the base directory (needed to
         *              prevent problems with an absolute path when using
         *              dir). Must not be <code>null</code>.
         * @param fast  Whether or not this call is part of a fast scan.
         *
         * @see #filesIncluded
         * @see #filesNotIncluded
         * @see #filesExcluded
         * @see #dirsIncluded
         * @see #dirsNotIncluded
         * @see #dirsExcluded
         * @see #slowScan
         */
        protected void scandir(FileInfo dir, String vpath, bool fast) {
            scandir(dir, new TokenizedPath(vpath), fast);
        }

        /**
         * Scan the given directory for files and directories. Found files and
         * directories are placed in their respective collections, based on the
         * matching of includes, excludes, and the selectors.  When a directory
         * is found, it is scanned recursively.
         *
         * @param dir   The directory to scan. Must not be <code>null</code>.
         * @param path The path relative to the base directory (needed to
         *              prevent problems with an absolute path when using
         *              dir). Must not be <code>null</code>.
         * @param fast  Whether or not this call is part of a fast scan.
         *
         * @see #filesIncluded
         * @see #filesNotIncluded
         * @see #filesExcluded
         * @see #dirsIncluded
         * @see #dirsNotIncluded
         * @see #dirsExcluded
         * @see #slowScan
         */
        private void scandir(FileInfo dir, TokenizedPath path, bool fast) {
            if (dir == null) throw new Exception("Dir must not be null.");

            String[] newfiles = null;
            if (dir.Attributes.HasFlag(FileAttributes.Directory)) {
                newfiles = Directory.GetFiles(dir.FullName)
                    .Concat(Directory.GetDirectories(dir.FullName))
                    .Select(file => file.Substring(dir.FullName.Length + Path.DirectorySeparatorChar.ToString().Length)).ToArray();
            }
            if (newfiles == null) {
                if (!dir.Exists) {
                    throw new Exception(dir + DOES_NOT_EXIST_POSTFIX);
                } else if (!dir.Attributes.HasFlag(FileAttributes.Directory)) 
                    throw new Exception($"{dir.FullName} is not a directory.");
                else {
                    throw new Exception($"IO error scanning directory '{dir.FullName}'");
                }
            }
            scandir(dir, path, fast, newfiles, new LinkedList<String>());
        }

        private void scandir(FileInfo dir, TokenizedPath path, bool fast, String[] newFiles, LinkedList<String> directoryNamesFollowed) {
            String vpath = path.ToString();
            if (!vpath.Equals("") && !vpath.EndsWith(Path.DirectorySeparatorChar.ToString())) 
                vpath += Path.DirectorySeparatorChar;

            // avoid double scanning of directories, can only happen in fast mode
            if (fast && hasBeenScanned(vpath)) return;
            if (!followSymlinks) {
                List<String> noLinks = new List<String>();
                foreach (String newFile in newFiles) {
                    FileInfo filePath;
                    if (dir == null)
                        filePath = new FileInfo(newFile);
                    else
                        filePath = new FileInfo(Path.Combine(dir.FullName, newFile));
                    if (filePath.Attributes.HasFlag(FileAttributes.ReparsePoint)) {
                        // Symbolic link
                        String name = vpath + newFile;
                        FileInfo file = new FileInfo(Path.Combine(dir.FullName, newFile));
                        if (file.Attributes.HasFlag(FileAttributes.Directory)) 
                            dirsExcluded.Add(name);
                        else if (file.Attributes.HasFlag(FileAttributes.Normal)) 
                            filesExcluded.Add(name);
                        accountForNotFollowedSymlink(name, file);
                    } else 
                        noLinks.Add(newFile);
                }
                newFiles = noLinks.ToArray();
            } else {
                directoryNamesFollowed.AddFirst(dir.FullName);
            }

            foreach (String newFile in newFiles) {
                String name = vpath + newFile;
                TokenizedPath newPath = new TokenizedPath(path, newFile);
                FileInfo file = new FileInfo(Path.Combine(dir.FullName, newFile));
                String[] children = null;
                if (file.Attributes.HasFlag(FileAttributes.Directory)) {
                    children = Directory.GetFiles(file.FullName)
                        .Concat(Directory.GetDirectories(file.FullName))
                        .Select(f => f.Substring(file.FullName.Length + Path.DirectorySeparatorChar.ToString().Length)).ToArray();
                }

                if (children == null || (children.Length == 0 && file.Attributes.HasFlag(FileAttributes.Normal))) {
                    if (isIncluded(newPath))
                        accountForIncludedFile(newPath, file);
                    else { 
                        everythingIncluded = false;
                        filesNotIncluded.Add(name);
                    }
                } else if (file.Attributes.HasFlag(FileAttributes.Directory)) { // dir
                    if (followSymlinks && causesIllegalSymlinkLoop(newFile, dir, directoryNamesFollowed)) {
                        // will be caught and redirected to Ant's logging system
                        Console.WriteLine($"skipping symbolic link {file.FullName} -- too many levels of symbolic links.");
                        notFollowedSymlinks.Add(file.FullName);
                        continue;
                    }

                    if (isIncluded(newPath)) {
                        accountForIncludedDir(newPath, file, fast, children,
                                              directoryNamesFollowed);
                    } else {
                        everythingIncluded = false;
                        dirsNotIncluded.Add(name);
                        if (fast && couldHoldIncluded(newPath) && !contentsExcluded(newPath)) {
                            scandir(file, newPath, fast, children, directoryNamesFollowed);
                        }
                    }
                    if (!fast) {
                        scandir(file, newPath, fast, children, directoryNamesFollowed);
                    }
                }
            }

            if (followSymlinks) {
                directoryNamesFollowed.RemoveFirst();
            }
        }

        /**
         * Process included file.
         * @param name  path of the file relative to the directory of the FileSet.
         * @param file  included File.
         */
        private void accountForIncludedFile(TokenizedPath name, FileInfo file) {
            processIncluded(name, file, filesIncluded, filesExcluded, filesDeselected);
        }

        /**
         * Process included directory.
         * @param name path of the directory relative to the directory of
         *             the FileSet.
         * @param file directory as File.
         * @param fast whether to perform fast scans.
         */
        private void accountForIncludedDir(TokenizedPath name, FileInfo file, bool fast) {
            processIncluded(name, file, dirsIncluded, dirsExcluded, dirsDeselected);
            if (fast && couldHoldIncluded(name) && !contentsExcluded(name)) {
                scandir(file, name, fast);
            }
        }

        private void accountForIncludedDir(TokenizedPath name, FileInfo file, bool fast, String[] children, LinkedList<String> directoryNamesFollowed) {
            processIncluded(name, file, dirsIncluded, dirsExcluded, dirsDeselected);
            if (fast && couldHoldIncluded(name) && !contentsExcluded(name)) {
                scandir(file, name, fast, children, directoryNamesFollowed);
            }
        }

        private void accountForNotFollowedSymlink(String name, FileInfo file) {
            accountForNotFollowedSymlink(new TokenizedPath(name), file);
        }

        private void accountForNotFollowedSymlink(TokenizedPath name, FileInfo file) {
            if (!isExcluded(name) && (isIncluded(name)
                    || (file.Attributes.HasFlag(FileAttributes.Directory) && couldHoldIncluded(name) && !contentsExcluded(name)))) {
                notFollowedSymlinks.Add(file.FullName);
            }
        }

        private void processIncluded(TokenizedPath path, FileInfo file, List<String> inc, List<String> exc, List<String> des) {
            String name = path.ToString();
            if (inc.Contains(name) || exc.Contains(name) || des.Contains(name)) return;
            bool included = false;
            if (isExcluded(path)) {
                exc.Add(name);
            } else if (isSelected(name, file)) {
                included = true;
                inc.Add(name);
            } else {
                des.Add(name);
            }
            everythingIncluded &= included;
        }
    
        /**
         * Test whether or not a name matches against at least one include
         * pattern.
         *
         * @param name The path to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against at least one
         *         include pattern, or <code>false</code> otherwise.
         */
        protected bool isIncluded(String name) {
            return isIncluded(new TokenizedPath(name));
        }

        /**
         * Test whether or not a name matches against at least one include
         * pattern.
         *
         * @param path The tokenized path to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against at least one
         *         include pattern, or <code>false</code> otherwise.
         */
        private bool isIncluded(TokenizedPath path) {
            ensureNonPatternSetsReady();

            String toMatch = path.ToString();
            if (!isCaseSensitive) 
                toMatch = toMatch.ToUpper();
            return includeNonPatterns.ContainsKey(toMatch) || includePatterns.Any(p => p.matchPath(path, isCaseSensitive));
        }

        /**
         * Test whether or not a name matches the start of at least one include
         * pattern.
         *
         * @param name The name to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against the start of at
         *         least one include pattern, or <code>false</code> otherwise.
         */
        protected bool couldHoldIncluded(String name) {
            return couldHoldIncluded(new TokenizedPath(name));
        }

        /**
         * Test whether or not a name matches the start of at least one include
         * pattern.
         *
         * @param tokenizedName The name to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against the start of at
         *         least one include pattern, or <code>false</code> otherwise.
         */
        private bool couldHoldIncluded(TokenizedPath tokenizedName) {
            return includePatterns.Concat(includeNonPatterns.Values.Select(item => item.ToPattern()))
                .Any(pat => couldHoldIncluded(tokenizedName, pat));
        }

        /**
         * Test whether or not a name matches the start of the given
         * include pattern.
         *
         * @param tokenizedName The name to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against the start of the
         *         include pattern, or <code>false</code> otherwise.
         */
        private bool couldHoldIncluded(TokenizedPath tokenizedName, TokenizedPattern tokenizedInclude) {
            return tokenizedInclude.matchStartOf(tokenizedName, isCaseSensitive)
                && isMorePowerfulThanExcludes(tokenizedName.ToString())
                && isDeeper(tokenizedInclude, tokenizedName);
        }

        /**
         * Verify that a pattern specifies files deeper
         * than the level of the specified file.
         * @param pattern the pattern to check.
         * @param name the name to check.
         * @return whether the pattern is deeper than the name.
         * @since Ant 1.6.3
         */
        private bool isDeeper(TokenizedPattern pattern, TokenizedPath name) {
            return pattern.containsPattern(SelectorUtils.DEEP_TREE_MATCH) || pattern.depth() > name.depth();
        }

        /**
         *  Find out whether one particular include pattern is more powerful
         *  than all the excludes.
         *  Note:  the power comparison is based on the length of the include pattern
         *  and of the exclude patterns without the wildcards.
         *  Ideally the comparison should be done based on the depth
         *  of the match; that is to say how many file separators have been matched
         *  before the first ** or the end of the pattern.
         *
         *  IMPORTANT : this function should return false "with care".
         *
         *  @param name the relative path to test.
         *  @return true if there is no exclude pattern more powerful than
         *  this include pattern.
         *  @since Ant 1.6
         */
        private bool isMorePowerfulThanExcludes(String name) {
            String soughtexclude = name + Path.DirectorySeparatorChar + SelectorUtils.DEEP_TREE_MATCH;
            return !excludePatterns.Select(p => p.ToString()).Any(s => s.Equals(soughtexclude));
        }

        /**
         * Test whether all contents of the specified directory must be excluded.
         * @param path the path to check.
         * @return whether all the specified directory's contents are excluded.
         */
        bool contentsExcluded(TokenizedPath path) {
            return
                excludePatterns
                .Where(pat => pat.endsWith(SelectorUtils.DEEP_TREE_MATCH))
                .Select(pat => pat.withoutLastToken())
                .Any(wlt => wlt.matchPath(path, isCaseSensitive));
        }

        /**
         * Test whether or not a name matches against at least one exclude
         * pattern.
         *
         * @param name The name to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against at least one
         *         exclude pattern, or <code>false</code> otherwise.
         */
        protected bool isExcluded(String name) {
            return isExcluded(new TokenizedPath(name));
        }

        /**
         * Test whether or not a name matches against at least one exclude
         * pattern.
         *
         * @param name The name to match. Must not be <code>null</code>.
         * @return <code>true</code> when the name matches against at least one
         *         exclude pattern, or <code>false</code> otherwise.
         */
        private bool isExcluded(TokenizedPath name) {
            ensureNonPatternSetsReady();

            String toMatch = name.ToString();
            if (!isCaseSensitive) {
                toMatch = toMatch.ToUpper();
            }
            return excludeNonPatterns.ContainsKey(toMatch)
                || excludePatterns.Any(p => p.matchPath(name, isCaseSensitive));
        }

        /**
         * Test whether a file should be selected.
         *
         * @param name the filename to check for selecting.
         * @param file the java.io.File object for this filename.
         * @return <code>false</code> when the selectors says that the file
         *         should not be selected, <code>true</code> otherwise.
         */
        protected bool isSelected(String name, FileInfo file) {
            return selectors == null
                || selectors.All(sel => sel.isSelected(basedir, name, file));
        }

        /**
         * Return the names of the files which matched at least one of the
         * include patterns and none of the exclude patterns.
         * The names are relative to the base directory.
         *
         * @return the names of the files which matched at least one of the
         *         include patterns and none of the exclude patterns.
         */
        public String[] getIncludedFiles() {
            String[] files;
            lock(this) {
                if (filesIncluded == null) {
                    throw new Exception("Must call scan() first");
                }
                files = filesIncluded.ToArray();
            }
            Array.Sort(files);
            return files;
        }

        /**
         * Return the count of included files.
         * @return <code>int</code>.
         * @since Ant 1.6.3
         */
        public int getIncludedFilesCount() {
            if (filesIncluded == null) 
                throw new Exception("Must call scan() first");
            return filesIncluded.Count;
        }

        /**
         * Return the names of the files which matched none of the include
         * patterns. The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.
         *
         * @return the names of the files which matched none of the include
         *         patterns.
         *
         * @see #slowScan
         */
        public String[] getNotIncludedFiles() {
            slowScan();
            return filesNotIncluded.ToArray();
        }

        /**
         * Return the names of the files which matched at least one of the
         * include patterns and at least one of the exclude patterns.
         * The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.
         *
         * @return the names of the files which matched at least one of the
         *         include patterns and at least one of the exclude patterns.
         *
         * @see #slowScan
         */
        public String[] getExcludedFiles() {
            slowScan();
            return filesExcluded.ToArray();
        }

        /**
         * <p>Return the names of the files which were selected out and
         * therefore not ultimately included.</p>
         *
         * <p>The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.</p>
         *
         * @return the names of the files which were deselected.
         *
         * @see #slowScan
         */
        public String[] getDeselectedFiles() {
            slowScan();
            return filesDeselected.ToArray();
        }

        /**
         * Return the names of the directories which matched at least one of the
         * include patterns and none of the exclude patterns.
         * The names are relative to the base directory.
         *
         * @return the names of the directories which matched at least one of the
         * include patterns and none of the exclude patterns.
         */
        public String[] getIncludedDirectories() {
            String[] directories;
            lock(this) {
                if (dirsIncluded == null) {
                    throw new Exception("Must call scan() first");
                }
                directories = dirsIncluded.ToArray();
            }
            Array.Sort(directories);
            return directories;
        }

        /**
         * Return the count of included directories.
         * @return <code>int</code>.
         * @since Ant 1.6.3
         */
        public int getIncludedDirsCount() {
            if (dirsIncluded == null) {
                throw new Exception("Must call scan() first");
            }
            return dirsIncluded.Count;
        }

        /**
         * Return the names of the directories which matched none of the include
         * patterns. The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.
         *
         * @return the names of the directories which matched none of the include
         * patterns.
         *
         * @see #slowScan
         */
        public String[] getNotIncludedDirectories() {
            slowScan();
            return dirsNotIncluded.ToArray();
        }

        /**
         * Return the names of the directories which matched at least one of the
         * include patterns and at least one of the exclude patterns.
         * The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.
         *
         * @return the names of the directories which matched at least one of the
         * include patterns and at least one of the exclude patterns.
         *
         * @see #slowScan
         */
        public String[] getExcludedDirectories() {
            slowScan();
            return dirsExcluded.ToArray();
        }

        /**
         * <p>Return the names of the directories which were selected out and
         * therefore not ultimately included.</p>
         *
         * <p>The names are relative to the base directory. This involves
         * performing a slow scan if one has not already been completed.</p>
         *
         * @return the names of the directories which were deselected.
         *
         * @see #slowScan
         */
        public String[] getDeselectedDirectories() {
            slowScan();
            return dirsDeselected.ToArray();
        }

        /**
         * Absolute paths of all symbolic links that haven't been followed
         * but would have been followed had followsymlinks been true or
         * maxLevelsOfSymlinks been bigger.
         *
         * @return sorted array of not followed symlinks
         * @since Ant 1.8.0
         * @see #notFollowedSymlinks
         */
        public String[] getNotFollowedSymlinks() {
            String[] links;
            lock(this) {
                links = notFollowedSymlinks.ToArray();
            }
            Array.Sort(links);
            return links;
        }

        /**
         * Add default exclusions to the current exclusions set.
         */
        public void addDefaultExcludes() {
            excludes = getDefaultExcludes()
                .Select(p => p.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar))
                .Concat(excludes).ToArray();
        }

        /**
         * Has the directory with the given path relative to the base
         * directory already been scanned?
         *
         * <p>Registers the given directory as scanned as a side effect.</p>
         *
         * @since Ant 1.6
         */
        private bool hasBeenScanned(String vpath) {
            return !scannedDirs.Add(vpath);
        }

        /**
         * Clear internal caches.
         *
         * @since Ant 1.6
         */
        private void clearCaches() {
            includeNonPatterns.Clear();
            excludeNonPatterns.Clear();
            includePatterns = null;
            excludePatterns = null;
            areNonPatternSetsReady = false;
        }

        /**
         * Ensure that the in|exclude &quot;patterns&quot;
         * have been properly divided up.
         *
         * @since Ant 1.6.3
         */
        /* package */
        void ensureNonPatternSetsReady() {
            if (!areNonPatternSetsReady) {
                includePatterns = fillNonPatternSet(includeNonPatterns, includes);
                excludePatterns = fillNonPatternSet(excludeNonPatterns, excludes);
                areNonPatternSetsReady = true;
            }
        }

        /**
         * Add all patterns that are not real patterns (do not contain
         * wildcards) to the set and returns the real patterns.
         *
         * @param map Map to populate.
         * @param patterns String[] of patterns.
         * @since Ant 1.8.0
         */
        private TokenizedPattern[] fillNonPatternSet(Dictionary<String, TokenizedPath> map, String[] patterns) {
            List<TokenizedPattern> al = new List<TokenizedPattern>(patterns.Length);
            foreach (String pattern in patterns) {
                if (SelectorUtils.hasWildcards(pattern)) {
                    al.Add(new TokenizedPattern(pattern));
                } else {
                    String s = isCaseSensitive ? pattern : pattern.ToUpper();
                    map.Add(s, new TokenizedPath(s));
                }
            }
            return al.ToArray();
        }

        /**
         * Would following the given directory cause a loop of symbolic
         * links deeper than allowed?
         *
         * <p>Can only happen if the given directory has been seen at
         * least more often than allowed during the current scan and it is
         * a symbolic link and enough other occurrences of the same name
         * higher up are symbolic links that point to the same place.</p>
         *
         * @since Ant 1.8.0
         */
        private bool causesIllegalSymlinkLoop(String dirName, FileInfo parent, LinkedList<String> directoryNamesFollowed) {
            try {
                FileInfo dirPath;
                if (parent == null) {
                    dirPath = new FileInfo(dirName);
                } else {
                    dirPath = new FileInfo(Path.Combine(parent.DirectoryName, dirName));
                }
                if (directoryNamesFollowed.Count >= maxLevelsOfSymlinks
                    && directoryNamesFollowed.Where(item => item.Equals(dirPath)).Count() >= maxLevelsOfSymlinks
                    && dirPath.Attributes.HasFlag(FileAttributes.ReparsePoint)) {

                    List<String> files = new List<String>();
                    FileInfo f = FILE_UTILS.resolveFile(parent, dirName);
                    String target = f.FullName;
                    files.Add(target);

                    StringBuilder relPath = new StringBuilder();
                    foreach (String dir in directoryNamesFollowed) {
                        relPath.Append("../");
                        if (dirName.Equals(dir)) {
                            f = FILE_UTILS.resolveFile(parent, relPath + dir);
                            files.Add(f.FullName);
                            if (files.Count > maxLevelsOfSymlinks
                                && files.Where(file => file.Equals(target)).Count() > maxLevelsOfSymlinks) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            } catch (Exception ex) {
                throw new Exception("Caught error while checking for symbolic links", ex);
            }
        }
    }
}
