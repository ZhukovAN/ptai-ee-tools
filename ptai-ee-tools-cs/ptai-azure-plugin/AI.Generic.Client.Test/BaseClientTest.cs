using System;
using AI.Enterprise.Integration.RestApi.Model;
using AI.Generic.Client;
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
            FileUtils.zip(
                @"D:\TEMP\20200131\app01",
                @"D:\TEMP\20200131\test.zip",
                new string[] { "**/*" } , 
                null, false, null, false);
        }

        [TestMethod]
        public void Scan() {
            string destFile = @"D:\TEMP\20200131\test.zip";
            FileUtils.zip(
                @"D:\TEMP\20200131\app01",
                destFile,
                new string[] { "**/*" },
                null, false, null, false);
            Client client = new Client("https://ptai-integration-service.domain.org:8443");
            client.init("admin", "ZqK99w5mB7HfNRnBbVJWa79eW0kT8FCr", null);
            client.scan("DEVEL.TEST.JAVA", destFile, "ptai");
        }
    }
}
