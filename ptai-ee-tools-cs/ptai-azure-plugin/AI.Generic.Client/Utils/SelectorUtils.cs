using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Utils {
    public class SelectorUtils {
        /**
         * The pattern that matches an arbitrary number of directories.
         * @since Ant 1.8.0
         */
        public static readonly String DEEP_TREE_MATCH = "**";

        private static readonly SelectorUtils instance = new SelectorUtils();

        private static readonly FileUtils FILE_UTILS = FileUtils.getFileUtils();

        /**
         * Private Constructor
         */
        private SelectorUtils() {}

        /**
         * Retrieves the instance of the Singleton.
         * @return singleton instance
         */
        public static SelectorUtils getInstance() {
            return instance;
        }

        /**
         * Tests whether or not a given path matches the start of a given
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
        public static bool matchPatternStart(String pattern, String str) {
            return matchPatternStart(pattern, str, true);
        }

        /**
         * Tests whether or not a given path matches the start of a given
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
        public static bool matchPatternStart(String pattern, String str,
                                                bool isCaseSensitive) {
            // When str starts with a File.separator, pattern has to start with a
            // File.separator.
            // When pattern starts with a File.separator, str has to start with a
            // File.separator.
            if (str.StartsWith(Path.DirectorySeparatorChar.ToString()) != pattern.StartsWith(Path.DirectorySeparatorChar.ToString()))
                return false;

            String[] patDirs = tokenizePathAsArray(pattern);
            String[] strDirs = tokenizePathAsArray(str);
            return matchPatternStart(patDirs, strDirs, isCaseSensitive);
        }


        /**
         * Tests whether or not a given path matches the start of a given
         * pattern up to the first "**".
         * <p>
         * This is not a general purpose test and should only be used if you
         * can live with false positives. For example, <code>pattern=**\a</code>
         * and <code>str=b</code> will yield <code>true</code>.
         *
         * @param patDirs The tokenized pattern to match against. Must not be
         *                <code>null</code>.
         * @param strDirs The tokenized path to match. Must not be
         *                <code>null</code>.
         * @param isCaseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         * @return whether or not a given path matches the start of a given
         * pattern up to the first "**".
         */
        public static bool matchPatternStart(String[] patDirs, String[] strDirs, bool isCaseSensitive) {
            int patIdxStart = 0;
            int patIdxEnd = patDirs.Length - 1;
            int strIdxStart = 0;
            int strIdxEnd = strDirs.Length - 1;

            // up to first '**'
            while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
                String patDir = patDirs[patIdxStart];
                if (patDir.Equals(DEEP_TREE_MATCH))
                    break;
                if (!match(patDir, strDirs[strIdxStart], isCaseSensitive))
                    return false;
                patIdxStart++;
                strIdxStart++;
            }

            // Fail if string is not exhausted or pattern is exhausted
            // Otherwise the pattern now holds ** while string is not exhausted
            // this will generate false positives but we can live with that.
            return strIdxStart > strIdxEnd || patIdxStart <= patIdxEnd;
        }

        /**
         * Tests whether or not a given path matches a given pattern.
         *
         * If you need to call this method multiple times with the same
         * pattern you should rather use TokenizedPath
         *
         * @see TokenizedPath
         *
         * @param pattern The pattern to match against. Must not be
         *                <code>null</code>.
         * @param str     The path to match, as a String. Must not be
         *                <code>null</code>.
         *
         * @return <code>true</code> if the pattern matches against the string,
         *         or <code>false</code> otherwise.
         */
        public static bool matchPath(String pattern, String str) {
            String[] patDirs = tokenizePathAsArray(pattern);
            return matchPath(patDirs, tokenizePathAsArray(str), true);
        }

        /**
         * Tests whether or not a given path matches a given pattern.
         *
         * If you need to call this method multiple times with the same
         * pattern you should rather use TokenizedPattern
         *
         * @see TokenizedPattern
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
        public static bool matchPath(String pattern, String str, bool isCaseSensitive) {
            String[] patDirs = tokenizePathAsArray(pattern);
            return matchPath(patDirs, tokenizePathAsArray(str), isCaseSensitive);
        }

        /**
         * Core implementation of matchPath.  It is isolated so that it
         * can be called from TokenizedPattern.
         */
        public static bool matchPath(String[] tokenizedPattern, String[] strDirs, bool isCaseSensitive) {
            int patIdxStart = 0;
            int patIdxEnd = tokenizedPattern.Length - 1;
            int strIdxStart = 0;
            int strIdxEnd = strDirs.Length - 1;

            // up to first '**'
            while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
                String patDir = tokenizedPattern[patIdxStart];
                if (patDir.Equals(DEEP_TREE_MATCH)) break;
                if (!match(patDir, strDirs[strIdxStart], isCaseSensitive)) return false;
                patIdxStart++;
                strIdxStart++;
            }
            if (strIdxStart > strIdxEnd) {
                // String is exhausted
                for (int i = patIdxStart; i <= patIdxEnd; i++) 
                    if (!tokenizedPattern[i].Equals(DEEP_TREE_MATCH)) return false;
                return true;
            }
            // String not exhausted, but pattern is. Failure.
            if (patIdxStart > patIdxEnd) return false;

            // up to last '**'
            while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
                String patDir = tokenizedPattern[patIdxEnd];
                if (patDir.Equals(DEEP_TREE_MATCH)) break;
                if (!match(patDir, strDirs[strIdxEnd], isCaseSensitive)) return false;
                patIdxEnd--;
                strIdxEnd--;
            }
            if (strIdxStart > strIdxEnd) {
                // String is exhausted
                for (int i = patIdxStart; i <= patIdxEnd; i++)
                    if (!tokenizedPattern[i].Equals(DEEP_TREE_MATCH)) return false;
                return true;
            }

            while (patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd) {
                int patIdxTmp = -1;
                for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
                    if (tokenizedPattern[i].Equals(DEEP_TREE_MATCH)) {
                        patIdxTmp = i;
                        break;
                    }
                }
                if (patIdxTmp == patIdxStart + 1) {
                    // '**/**' situation, so skip one
                    patIdxStart++;
                    continue;
                }
                // Find the pattern between padIdxStart & padIdxTmp in str between
                // strIdxStart & strIdxEnd
                int patLength = (patIdxTmp - patIdxStart - 1);
                int strLength = (strIdxEnd - strIdxStart + 1);
                int foundIdx = -1;
            
                for (int i = 0; i <= strLength - patLength; i++) {
                    bool breakFlag = false;
                    for (int j = 0; j < patLength; j++) {
                        String subPat = tokenizedPattern[patIdxStart + j + 1];
                        String subStr = strDirs[strIdxStart + i + j];
                        if (!match(subPat, subStr, isCaseSensitive)) {
                            breakFlag = true;
                            break;
                        }
                    }
                    if (breakFlag) continue;
                    foundIdx = strIdxStart + i;
                    break;
                }
                if (foundIdx == -1) return false;

                patIdxStart = patIdxTmp;
                strIdxStart = foundIdx + patLength;
            }

            for (int i = patIdxStart; i <= patIdxEnd; i++)
                if (!DEEP_TREE_MATCH.Equals(tokenizedPattern[i])) return false;
            return true;
        }

        /**
         * Tests whether or not a string matches against a pattern.
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
            return match(pattern, str, true);
        }

        /**
         * Tests whether or not a string matches against a pattern.
         * The pattern may contain two special characters:<br>
         * '*' means zero or more characters<br>
         * '?' means one and only one character
         *
         * @param pattern The pattern to match against.
         *                Must not be <code>null</code>.
         * @param str     The string which must be matched against the pattern.
         *                Must not be <code>null</code>.
         * @param caseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         *
         * @return <code>true</code> if the string matches against the pattern,
         *         or <code>false</code> otherwise.
         */
        public static bool match(String pattern, String str, bool caseSensitive) {
            char[] patArr = pattern.ToCharArray();
            char[] strArr = str.ToCharArray();
            int patIdxStart = 0;
            int patIdxEnd = patArr.Length - 1;
            int strIdxStart = 0;
            int strIdxEnd = strArr.Length - 1;

            bool containsStar = false;
            foreach (char ch in patArr) {
                if (ch == '*') {
                    containsStar = true;
                    break;
                }
            }

            if (!containsStar) {
                // No '*'s, so we make a shortcut
                if (patIdxEnd != strIdxEnd) return false; // Pattern and string do not have the same size
                for (int i = 0; i <= patIdxEnd; i++) {
                    char ch = patArr[i];
                    if (ch != '?' && different(caseSensitive, ch, strArr[i])) return false; // Character mismatch
                }
                return true; // String matches against pattern
            }

            if (patIdxEnd == 0) return true; // Pattern contains only '*', which matches anything

            // Process characters before first star
            while (true) {
                char ch = patArr[patIdxStart];
                if (ch == '*' || strIdxStart > strIdxEnd) break;
                if (ch != '?' && different(caseSensitive, ch, strArr[strIdxStart])) return false; // Character mismatch
                patIdxStart++;
                strIdxStart++;
            }
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            if (strIdxStart > strIdxEnd) return allStars(patArr, patIdxStart, patIdxEnd);

            // Process characters after last star
            while (true) {
                char ch = patArr[patIdxEnd];
                if (ch == '*' || strIdxStart > strIdxEnd) break;
                if (ch != '?' && different(caseSensitive, ch, strArr[strIdxEnd])) return false; // Character mismatch
                patIdxEnd--;
                strIdxEnd--;
            }
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            if (strIdxStart > strIdxEnd) return allStars(patArr, patIdxStart, patIdxEnd);

            // process pattern between stars. padIdxStart and patIdxEnd point
            // always to a '*'.
            while (patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd) {
                int patIdxTmp = -1;
                for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
                    if (patArr[i] == '*') {
                        patIdxTmp = i;
                        break;
                    }
                }
                if (patIdxTmp == patIdxStart + 1) {
                    // Two stars next to each other, skip the first one.
                    patIdxStart++;
                    continue;
                }
                // Find the pattern between padIdxStart & padIdxTmp in str between
                // strIdxStart & strIdxEnd
                int patLength = (patIdxTmp - patIdxStart - 1);
                int strLength = (strIdxEnd - strIdxStart + 1);
                int foundIdx = -1;

                for (int i = 0; i <= strLength - patLength; i++) {
                    bool breakFlag = false;
                    for (int j = 0; j < patLength; j++) {
                        char ch = patArr[patIdxStart + j + 1];
                        if (ch != '?' && different(caseSensitive, ch, strArr[strIdxStart + i + j])) {
                            breakFlag = true;
                            break;
                        }
                    }
                    if (breakFlag) continue;
                    foundIdx = strIdxStart + i;
                    break;
                }

                if (foundIdx == -1) return false;
                patIdxStart = patIdxTmp;
                strIdxStart = foundIdx + patLength;
            }

            // All characters in the string are used. Check if only '*'s are left
            // in the pattern. If so, we succeeded. Otherwise failure.
            return allStars(patArr, patIdxStart, patIdxEnd);
        }

        private static bool allStars(char[] chars, int start, int end) {
            for (int i = start; i <= end; ++i)
                if (chars[i] != '*') return false;
            return true;
        }

        private static bool different(
            bool caseSensitive, char ch, char other) {
            return caseSensitive 
                ? ch != other
                : Char.ToUpper(ch) != Char.ToUpper(other);
        }

        /**
         * Breaks a path up into a Vector of path elements, tokenizing on
         * <code>File.separator</code>.
         *
         * @param path Path to tokenize. Must not be <code>null</code>.
         *
         * @return a Vector of path elements from the tokenized path
         */
        public static List<String> tokenizePath(String path) {
            return tokenizePath(path, Path.DirectorySeparatorChar.ToString());
        }

        /**
         * Breaks a path up into a Vector of path elements, tokenizing on
         *
         * @param path Path to tokenize. Must not be <code>null</code>.
         * @param separator the separator against which to tokenize.
         *
         * @return a Vector of path elements from the tokenized path
         * @since Ant 1.6
         */
        public static List<String> tokenizePath(String path, String separator) {
            List<String> ret = new List<String>();
            if (FileUtils.isAbsolutePath(path)) {
                String[] s = FILE_UTILS.dissect(path);
                ret.Add(s[0]);
                path = s[1];
            }
            String[] lines = path.Split(new String[] { separator }, StringSplitOptions.None);
            foreach (String line in lines)
                ret.Add(line);
            return ret;
        }

        /**
         * Same as {@link #tokenizePath tokenizePath} but hopefully faster.
         */
        /* package */
        public static String[] tokenizePathAsArray(String path) {
            String root = null;
            if (FileUtils.isAbsolutePath(path)) {
                String[] s = FILE_UTILS.dissect(path);
                root = s[0];
                path = s[1];
            }
            char sep = Path.DirectorySeparatorChar;
            int start = 0;
            int len = path.Length;
            int count = 0;
            for (int pos = 0; pos < len; pos++) {
                if (path[pos] == sep) {
                    if (pos != start) count++;
                    start = pos + 1;
                }
            }
            if (len != start) count++;
            String[] l = new String[count + ((root == null) ? 0 : 1)];

            if (root != null) {
                l[0] = root;
                count = 1;
            } else count = 0;
            start = 0;
            for (int pos = 0; pos < len; pos++) {
                if (path[pos] == sep) {
                    if (pos != start) {
                        String tok = path.Substring(start, pos - start);
                        l[count++] = tok;
                    }
                    start = pos + 1;
                }
            }
            if (len != start) {
                String tok = path.Substring(start);
                l[count/*++*/] = tok;
            }
            return l;
        }

        protected static readonly char[] separators = new char[] { ' ', '\t', '\n', '\r', '\f' };

        /**
         * "Flattens" a string by removing all whitespace (space, tab, linefeed,
         * carriage return, and formfeed). This uses StringTokenizer and the
         * default set of tokens as documented in the single argument constructor.
         *
         * @param input a String to remove all whitespace.
         * @return a String that has had all whitespace removed.
         */
        public static String removeWhitespace(String input) {
            StringBuilder result = new StringBuilder();
            if (input != null) {
                String[] lines = input.Split(separators);
                foreach(String line in lines)
                    result.Append(line);
            }
            return result.ToString();
        }

        /**
         * Tests if a string contains stars or question marks
         * @param input a String which one wants to test for containing wildcard
         * @return true if the string contains at least a star or a question mark
         */
        public static bool hasWildcards(String input) {
            return input.Contains("*") || input.Contains("?");
        }

        /**
         * removes from a pattern all tokens to the right containing wildcards
         * @param input the input string
         * @return the leftmost part of the pattern without wildcards
         */
        public static String rtrimWildcardTokens(String input) {
            return new TokenizedPattern(input).rtrimWildcardTokens().ToString();
        }
    }
}
