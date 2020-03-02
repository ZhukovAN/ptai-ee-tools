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

        public int scan(string name, string zip, string nodeName, string stagingFolder) {
            int res = -1000;
            this.Login();
            this.sast.Configuration.AddApiKey("Authorization", "Bearer " + this.jwt.AccessToken);
            String uploadId = Guid.NewGuid().ToString();
            const long chunkSize = 1024 * 1024;
            if (chunkSize > Int32.MaxValue) throw new Exception("File chunk size too big");
            long length = new FileInfo(zip).Length;
            Console.WriteLine($"Prepare to upload {FileUtils.BytesToString(length)} of sources");

            if (length <= chunkSize) {
                this.sast.UploadUsingPOST(0, File.OpenRead(zip), name, 1, uploadId); 
                Console.WriteLine("Uploaded as single part");
            } else {
                using (FileStream input = File.OpenRead(zip)) {
                    const int bufferSize = 512 * 1024;
                    byte[] buffer = new byte[bufferSize];

                    long totalBytesToRead = length;
                    // Some kind of math magic to ceil round division result
                    long partsNumber = (totalBytesToRead + chunkSize - 1) / chunkSize;
                    for (long i = 0; i < partsNumber; i++) {
                        long chunkBytesToRead = totalBytesToRead > chunkSize ? chunkSize : totalBytesToRead;
                        long readsNumber = (chunkBytesToRead + bufferSize - 1) / bufferSize;
                        FileInfo chunkFile = new FileInfo(Path.GetTempFileName());
                        chunkFile.Attributes = FileAttributes.Temporary;
                        using (FileStream output = File.OpenWrite(chunkFile.FullName)) {
                            for (long j = 0; j < readsNumber; j++) {
                                long bytesToRead = chunkBytesToRead > bufferSize ? bufferSize : chunkBytesToRead;
                                int bytesRead = input.Read(buffer, 0, (int)bytesToRead);
                                if (-1 == bytesRead) break;
                                output.Write(buffer, 0, bytesRead);
                                chunkBytesToRead -= bytesRead;
                                totalBytesToRead -= bytesRead;
                            }
                        }
                        this.sast.UploadUsingPOST(i, File.OpenRead(chunkFile.FullName), name, partsNumber, uploadId);
                        Console.WriteLine($"Uploaded part {i} of {partsNumber}");
                        chunkFile.Delete();
                    }
                }
            }
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
            List<string> results = sast.GetJobResultsUsingGET(scanId);
            foreach (String result in results) {
                Stream data = sast.GetJobResultUsingGET(scanId, result);
                String fileName = Path.Combine(stagingFolder, result.Replace("REPORTS", ".ptai"));
                Directory.CreateDirectory(Path.GetDirectoryName(fileName));
                if (fileName.EndsWith("status.code")) {
                    using (StreamWriter output = new StreamWriter(fileName)) {
                        String code = new StreamReader(data).ReadToEnd();
                        output.WriteLine(code);
                        res = Int32.Parse(code);
                    }
                } else {
                    using (FileStream output = File.OpenWrite(fileName)) {
                        data.CopyTo(output);
                    }
                }
            }
            return res;
        }
    }
}
