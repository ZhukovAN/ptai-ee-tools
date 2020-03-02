using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Utils {
    public class TokenizedPath {
        /**
         * Instance that holds no tokens at all.
         */
        public static readonly TokenizedPath EMPTY_PATH = new TokenizedPath("", new String[0]);

        /** Helper. */
        private static readonly FileUtils FILE_UTILS = FileUtils.getFileUtils();
        /** iterations for case-sensitive scanning. */
        private static readonly bool[] CS_SCAN_ONLY = new bool[] {true};
        /** iterations for non-case-sensitive scanning. */
        private static readonly bool[] CS_THEN_NON_CS = new bool[] {true, false};

        private readonly String path;
        private readonly String[] tokenizedPath;

        /**
        * Initialize the TokenizedPath by parsing it.
        * @param path The path to tokenize. Must not be
        *                <code>null</code>.
        */
        public TokenizedPath(String path) : this(path, SelectorUtils.tokenizePathAsArray(path)) { }

        /**
         * Creates a new path as a child of another path.
         *
         * @param parent the parent path
         * @param child the child, must not contain the file separator
         */
        public TokenizedPath(TokenizedPath parent, String child) {
            if (!String.IsNullOrEmpty(parent.path) && parent.path[parent.path.Length - 1] != Path.DirectorySeparatorChar)
                path = parent.path + Path.DirectorySeparatorChar + child;
            else 
                path = parent.path + child;
            tokenizedPath = new String[parent.tokenizedPath.Length + 1];
            parent.tokenizedPath.CopyTo(tokenizedPath, 0);
            tokenizedPath[parent.tokenizedPath.Length] = child;
        }

        /* package */
        public TokenizedPath(String path, String[] tokens) {
            this.path = path;
            this.tokenizedPath = tokens;
        }

        /**
         * @return The original path String
         */
        public override String ToString() {
            return path;
        }

        /**
         * The depth (or length) of a path.
         * @return int
         */
        public int depth() {
            return tokenizedPath.Length;
        }

        /* package */
        public String[] getTokens() {
            return tokenizedPath;
        }

        /**
         * From <code>base</code> traverse the filesystem in order to find
         * a file that matches the given name.
         *
         * @param base base File (dir).
         * @param cs whether to scan case-sensitively.
         * @return File object that points to the file in question or null.
         */
        public FileInfo findFile(FileInfo file, bool cs) {
            String[] tokens = tokenizedPath;
            if (FileUtils.isAbsolutePath(path)) {
                if (file == null) {
                    String[] s = FILE_UTILS.dissect(path);
                    file = new FileInfo(s[0]);
                    tokens = SelectorUtils.tokenizePathAsArray(s[1]);
                } else {
                    FileInfo f = FILE_UTILS.normalize(path);
                    String s = FILE_UTILS.removeLeadingPath(file, f);
                    if (s.Equals(f.FullName)) {
                        //removing base from path yields no change; path
                        //not child of base
                        return null;
                    }
                    tokens = SelectorUtils.tokenizePathAsArray(s);
                }
            }
            return findFile(file, tokens, cs);
        }

        /**
         * Do we have to traverse a symlink when trying to reach path from
         * basedir?
         * @param base base File (dir).
         * @return boolean
         */
        public bool isSymlink(FileInfo file) {
            foreach (String token in tokenizedPath) {
                FileInfo pathToTraverse;
                if (file == null)
                    pathToTraverse = new FileInfo(token);
                else
                    pathToTraverse = new FileInfo(Path.Combine(file.FullName, token));
                if (pathToTraverse.Attributes.HasFlag(FileAttributes.ReparsePoint)) return true;
                file = new FileInfo(Path.Combine(file.FullName, token));
            }
            return false;
        }

        /**
         * true if the original paths are equal.
         * @return boolean
         */
        /*
        @Override
            public boolean equals(Object o) {
            return o instanceof TokenizedPath
                    && path.equals(((TokenizedPath)o).path);
        }

        @Override
            public int hashCode() {
            return path.hashCode();
        }
        */
        /**
         * From <code>base</code> traverse the filesystem in order to find
         * a file that matches the given stack of names.
         *
         * @param base base File (dir) - must not be null.
         * @param pathElements array of path elements (dirs...file).
         * @param cs whether to scan case-sensitively.
         * @return File object that points to the file in question or null.
         */
        private static FileInfo findFile(FileInfo file, String[] pathElements, bool cs) {
            foreach (String pathElement in pathElements) {
                if (!file.Attributes.HasFlag(FileAttributes.Directory)) return null;
                String[] files = Directory.GetFiles(file.FullName);
                if (files == null) {
                    throw new Exception($"IO error scanning directory {file.FullName}");
                }
                bool found = false;
                bool[] matchCase = cs ? CS_SCAN_ONLY : CS_THEN_NON_CS;
                for (int i = 0; !found && i < matchCase.Length; i++) {
                    for (int j = 0; !found && j < files.Length; j++) {
                        if (matchCase[i]
                                ? files[j].Equals(pathElement)
                                : files[j].Equals(pathElement, StringComparison.OrdinalIgnoreCase)) {
                            file = new FileInfo(Path.Combine(file.FullName, files[j]));
                            found = true;
                        }
                    }
                }
                if (!found) return null;
            }
            return pathElements.Length == 0 && !file.Attributes.HasFlag(FileAttributes.Directory) ? null : file;
        }

        /**
         * Creates a TokenizedPattern from the same tokens that make up
         * this path.
         *
         * @return TokenizedPattern
         */
        public TokenizedPattern ToPattern() {
            return new TokenizedPattern(path, tokenizedPath);
        }
    }
}
