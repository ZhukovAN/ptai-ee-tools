using System;
using System.IO;
using System.IO.Compression;
using AI.Generic.Client.Test.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AI.Generic.Client.Test {
    [TestClass]
    public class PluginTest {
        [TestMethod]
        [DeploymentItem(@"TestData\code\test.java.zip")]
        public void TestLocalScan() {
            using (
                TempStorage temp = new TempStorage(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()))) {
                String srcDir = Path.Combine(temp.Path, "src");
                String stagingDir = Path.Combine(temp.Path, "staging");
                String tempDir = Path.Combine(temp.Path, "temp");
                ZipFile.ExtractToDirectory("test.java.zip", srcDir);
                Plugin plugin = new Plugin(
                    false.ToString(), null, null, null, null,
                    null,
                    "**/*",
                    "**/target/**, **/*.json, **/*.xml",
                    null, true.ToString(), false.ToString(),
                    "DEVEL.TEST.JAVA", null, null, srcDir, tempDir, stagingDir);
                int res = plugin.scan();
            }
        }

        [TestMethod]
        [DeploymentItem(@"TestData\code\test.java.zip")]
        [DeploymentItem(@"TestData\x509\ca.chain.pem.crt")]
        public void TestRemoteScan() {
            using (
                TempStorage temp = new TempStorage(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()))) {
                String srcDir = Path.Combine(temp.Path, "src");
                String stagingDir = Path.Combine(temp.Path, "staging");
                String tempDir = Path.Combine(temp.Path, "temp");
                ZipFile.ExtractToDirectory("test.java.zip", srcDir);
                Plugin plugin = new Plugin(
                    true.ToString(), 
                    @"https://ptai-integration-service.domain.org:8443", "admin", "t01UYriFaSsfUvS3RV5q1FrzL5nd6M6F", 
                    File.ReadAllText("ca.chain.pem.crt"),
                    "ptai",
                    "**/*",
                    "**/target/**, **/*.json, **/*.xml",
                    null, true.ToString(), false.ToString(),
                    "DEVEL.TEST.JAVA", null, null, srcDir, tempDir, stagingDir);
                int res = plugin.scan();
            }
        }
    }
}
