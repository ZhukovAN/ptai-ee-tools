using System;
using AI.Enterprise.Integration.RestApi.Model;
using AI.Generic.Client;
using AI.Generic.Client.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AI.Azure.Plugin.Test {
    [TestClass]
    public class BaseClientTest {
        [TestMethod]
        public void GetJwt() {
            BaseClient client = new BaseClient("https://ptai-integration-service.domain.org:8443");
            client.init("admin", "ZqK99w5mB7HfNRnBbVJWa79eW0kT8FCr", null);
            JwtResponse jwt = client.Login();
            jwt = client.Login();
        }

        [TestMethod]
        public void Zip() {
            Generic.Client.FileUtils.zip(
                @"D:\TEMP\20200214\App01",
                @"D:\TEMP\20200131\test.zip",
                new string[] { "**/*" } ,
                new string[] { "**/target/**", "**/*.json", "**/*.xml" }, true, "src/main", false);
                // null, true, "src/main", true);
        }

        [TestMethod]
        public void Scan() {
            string destFile = @"D:\TEMP\20200131\test.zip";
            Generic.Client.FileUtils.zip(
                @"D:\TEMP\20200131\app01",
                destFile,
                new string[] { "**/*" },
                null, false, null, false);
            Client client = new Client("https://ptai-integration-service.domain.org:8443");
            client.init("admin", "ZqK99w5mB7HfNRnBbVJWa79eW0kT8FCr", null);
            // client.scan("DEVEL.TEST.JAVA", destFile, "ptai");
        }

        [TestMethod]
        public void ScanFolders() {
            DirectoryScanner scanner = new DirectoryScanner();
            scanner.setBasedir(@"D:\TEMP\20200214\App01");
            // scanner.setIncludes(new String[] { "**/*.java" });
            scanner.setIncludes(new String[] { "**/*" });
            scanner.setExcludes(new String[] { "**/target/**" });
            scanner.addDefaultExcludes();
            scanner.scan();
            String[] files = scanner.getIncludedFiles();
            foreach (String file in files)
                Console.WriteLine(file);
        }

        [TestMethod]
        public void CopyFolders() {
            Generic.Client.FileUtils.copy(
                @"D:\TEMP\20200214\App01", @"D:\TEMP\20200217", 
                new string[] { "**/*" },
                new string[] { "**/target/**", "**/*.json", "**/*.xml" }, true, "src/main", false);
        }
    }
}
