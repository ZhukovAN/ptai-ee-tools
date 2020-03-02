using AI.Generic.Client.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client {
    public class FileUtils {
        public class FileEntry {
            public string file;
            public string entry;
            public FileEntry(string file, string entry) {
                this.file = file;
                this.entry = entry;
            }
        }

        public static List<FileEntry> collect(string folder, string[] includes, string[] excludes, bool usePredefinedExcludes, string removePrefix, bool flatten) {
            DirectoryScanner scanner = new DirectoryScanner();
            scanner.setBasedir(folder);
            scanner.setIncludes(includes);
            scanner.setExcludes(excludes);
            if (usePredefinedExcludes)
                scanner.addDefaultExcludes();
            scanner.scan();
            String[] files = scanner.getIncludedFiles();
            List<FileEntry> res = new List<FileEntry>();
            foreach (String file in files) {
                String entry = file;
                if (flatten)
                    entry = Path.GetFileName(folder + Path.DirectorySeparatorChar + file);
                else if (!String.IsNullOrEmpty(removePrefix)) {
                    String normalizedPrefix = removePrefix.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
                    if (entry.StartsWith(normalizedPrefix))
                        entry = entry.Substring(normalizedPrefix.Length);
                    else
                        throw new Exception($"Can't remove prefix {removePrefix} from entry {entry}");
                }
                if (!res.Any(e => e.entry.Equals(entry)))
                    res.Add(new FileEntry(folder + Path.DirectorySeparatorChar + file, entry));
            }
            return res;
        }

        public static void zip(string folder, string destination, string[] includes, string[] excludes, bool usePredefinedExcludes, string removePrefix, bool flatten) {
            byte[] buf = new byte[1024 * 100];

            List<FileEntry> entries = collect(folder, includes, excludes, usePredefinedExcludes, removePrefix, flatten);
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

        public static void copy(string folder, string destination, string[] includes, string[] excludes, bool usePredefinedExcludes, string removePrefix, bool flatten) {
            List<FileEntry> entries = collect(folder, includes, excludes, usePredefinedExcludes, removePrefix, flatten);
            foreach (FileEntry entry in entries) {
                String destFileName = destination + Path.DirectorySeparatorChar + entry.entry;
                Directory.CreateDirectory(Path.GetDirectoryName(destFileName));
                File.Copy(entry.file, destFileName);
            }
        }

        public static String BytesToString(long byteCount) {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; // Longs run out around EB
            if (0 == byteCount) return "0 " + suf[0];
            long bytes = Math.Abs(byteCount);
            int idx = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, idx), 1);
            return (Math.Sign(byteCount) * num).ToString() + " " + suf[idx];
        }
    }
}
