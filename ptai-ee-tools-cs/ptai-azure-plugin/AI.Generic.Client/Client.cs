using AI.Enterprise.Integration.RestApi.Api;
using AI.Enterprise.Integration.RestApi.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AI.Generic.Client {
    public class Client : BaseClient {
        protected ISastControllerApi sast = null;

        public Client(string basePath) : base(basePath) {
            this.sast = new SastControllerApi(basePath);
            Console.WriteLine("Base path is " + basePath);
        }

        public void scan(string name, string zip, string nodeName) {
            this.Login();
            this.sast.Configuration.AddApiKey("Authorization", "Bearer " + this.jwt.AccessToken);
            this.sast.UploadUsingPOST(0, File.OpenRead(zip), name, 1);
            int scanId = sast.ScanUiManagedUsingPOST(name, nodeName);

            int pos = 0;
            do {
                JobState state = sast.GetJobStateUsingGET(scanId, pos);
                if (pos != state.Pos) {
                    string[] lines = Regex.Split(state.Log, @"\r?\n");
                    foreach (string line in lines)
                        Console.WriteLine(line);
                }
                pos = state.Pos;
                if (JobState.StatusEnum.UNKNOWN != state.Status) break;
                Thread.Sleep(2000);
            } while (true);
        }
    }
}
