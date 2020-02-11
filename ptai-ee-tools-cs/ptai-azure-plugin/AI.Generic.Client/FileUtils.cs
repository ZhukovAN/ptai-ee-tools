using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Azure.Plugin {
    public class FileUtils {
        protected static readonly char WINDOWS_SEPARATOR = '\\';
        protected static readonly char UNIX_SEPARATOR = '/';

        public static readonly string[] PREDEFINED_EXCLUDES = new string[] { "**/%*%", "**/.git/**", "**/SCCS", "**/.bzr", "**/.hg/**", "**/.bzrignore", "**/.git", "**/SCCS/**", "**/.hg", "**/.#*", "**/vssver.scc", "**/.bzr/**", "**/._*", "**/#*#", "**/*~", "**/CVS", "**/.hgtags", "**/.svn/**", "**/.hgignore", "**/.svn", "**/.gitignore", "**/.gitmodules", "**/.hgsubstate", "**/.gitattributes", "**/CVS/**", "**/.hgsub", "**/.DS_Store", "**/.cvsignore" };

        public class FileEntry {
            public string file;
            public string entry;
            public FileEntry(string file, string entry) {
                this.file = file;
                this.entry = entry;
            }
        }

        public static void collect(List<FileEntry> list, string rootFolder, string currentFolder, string[] includes, string[] excludes, bool usePredefinedExcludes, string removePrefix, bool flatten) {
            string[] files = Directory.GetFiles(currentFolder);
            foreach (string file in files) {
                string relativePath = file.Substring(rootFolder.Length);
                if (relativePath.StartsWith(Path.DirectorySeparatorChar.ToString()))
                    relativePath = relativePath.Substring(Path.DirectorySeparatorChar.ToString().Length);
                // relativePath = check(relativePath, includes, excludes, usePredefinedExcludes, removePrefix, flatten, true);
                // if ("" == relativePath) continue;
                list.Add(new FileEntry(file, relativePath));
            }
            string[] folders = Directory.GetDirectories(currentFolder);
            foreach (string folder in folders)
                collect(list, rootFolder, folder, includes, excludes, usePredefinedExcludes, removePrefix, flatten);
        }

        public static void zip(string folder, string destination, string[] includes, string[] excludes, bool usePredefinedExcludes, string removePrefix, bool flatten) {
            List<FileEntry> entries = new List<FileEntry>();
            byte[] buf = new byte[1024 * 100];

            collect(entries, folder, folder, includes, excludes, usePredefinedExcludes, removePrefix, flatten);
            using (FileStream zip = new FileStream(destination, FileMode.Create)) {
                using (ZipArchive archive = new ZipArchive(zip, ZipArchiveMode.Update)) {
                    foreach (FileEntry entry in entries) {
                        using (BinaryReader reader = new BinaryReader(File.OpenRead(entry.file))) {
                            ZipArchiveEntry zipEntry = archive.CreateEntry(entry.entry);

                            using (BinaryWriter writer = new BinaryWriter(zipEntry.Open())) {
                                while (true) {
                                    int sz = reader.Read(buf, 0, buf.Length);
                                    if (sz <= 0) break;
                                    writer.Write(buf, 0, sz);
                                    if (sz < buf.Length) break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
