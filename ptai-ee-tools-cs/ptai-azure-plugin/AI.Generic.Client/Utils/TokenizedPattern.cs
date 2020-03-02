using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Utils {
    public class TokenizedPattern {
        /**
         * Instance that holds no tokens at all.
         */
        public static readonly TokenizedPattern EMPTY_PATTERN = new TokenizedPattern("", new String[0]);

        private readonly String pattern;
        private readonly String[] tokenizedPattern;

        /**
        * Initialize the PathPattern by parsing it.
        * @param pattern The pattern to match against. Must not be
        *                <code>null</code>.
        */
        public TokenizedPattern(String pattern) : this(pattern, SelectorUtils.tokenizePathAsArray(pattern)) { }

        public TokenizedPattern(String pattern, String[] tokens) {
            this.pattern = pattern;
            this.tokenizedPattern = tokens;
        }

        /**
         * Tests whether or not a given path matches a given pattern.
         *
         * @param path    The path to match, as a String. Must not be
         *                <code>null</code>.
         * @param isCaseSensitive Whether or not matching should be performed
         *                        case sensitively.
         *
         * @return <code>true</code> if the pattern matches against the string,
         *         or <code>false</code> otherwise.
         */
        public bool matchPath(TokenizedPath path, bool isCaseSensitive) {
            return SelectorUtils.matchPath(tokenizedPattern, path.getTokens(), isCaseSensitive);
        }

        /**
         * Tests whether or not this pattern matches the start of
         * a path.
         *
         * @param path TokenizedPath
         * @param caseSensitive boolean
         * @return boolean
         */
        public bool matchStartOf(TokenizedPath path, bool caseSensitive) {
            return SelectorUtils.matchPatternStart(tokenizedPattern, path.getTokens(), caseSensitive);
        }

        /**
         * @return The pattern String
         */
        public String toString() {
            return pattern;
        }

        public String getPattern() {
            return pattern;
        }

        /**
         * true if the original patterns are equal.
         *
         * @param o Object
         */
        public bool equals(Object o) {
            return o is TokenizedPattern && pattern.Equals(((TokenizedPattern)o).pattern);
        }

        /**
         * The depth (or length) of a pattern.
         *
         * @return int
         */
        public int depth() {
            return tokenizedPattern.Length;
        }

        /**
         * Does the tokenized pattern contain the given string?
         *
         * @param pat String
         * @return boolean
         */
        public bool containsPattern(String pat) {
            return tokenizedPattern.Contains(pat);
        }

        /**
         * Returns a new TokenizedPath where all tokens of this pattern to
         * the right containing wildcards have been removed
         *
         * @return the leftmost part of the pattern without wildcards
         */
        public TokenizedPath rtrimWildcardTokens() {
            StringBuilder sb = new StringBuilder();
            int newLen = 0;
            for (; newLen < tokenizedPattern.Length; newLen++) {
                if (SelectorUtils.hasWildcards(tokenizedPattern[newLen])) break;
                if (newLen > 0 && sb[sb.Length - 1] != Path.DirectorySeparatorChar) 
                    sb.Append(Path.DirectorySeparatorChar);
                sb.Append(tokenizedPattern[newLen]);
            }
            if (newLen == 0) 
                return TokenizedPath.EMPTY_PATH;
            String[] newPats = new String[newLen];
            Array.Copy(tokenizedPattern, 0, newPats, 0, newLen);
            return new TokenizedPath(sb.ToString(), newPats);
        }

        /**
         * true if the last token equals the given string.
         *
         * @param s String
         * @return boolean
         */
        public bool endsWith(String s) {
            return tokenizedPattern.Length > 0 && tokenizedPattern[tokenizedPattern.Length - 1].Equals(s);
        }

        /**
         * Returns a new pattern without the last token of this pattern.
         *
         * @return TokenizedPattern
         */
        public TokenizedPattern withoutLastToken() {
            if (tokenizedPattern.Length == 0) {
                throw new Exception("Can't strip a token from nothing");
            }
            if (tokenizedPattern.Length == 1) return EMPTY_PATTERN;
            String toStrip = tokenizedPattern[tokenizedPattern.Length - 1];
            int index = pattern.LastIndexOf(toStrip);
            String[] tokens = new String[tokenizedPattern.Length - 1];
            Array.Copy(tokenizedPattern, 0, tokens, 0, tokenizedPattern.Length - 1);
            return new TokenizedPattern(pattern.Substring(0, index), tokens);
        }
    }
}
