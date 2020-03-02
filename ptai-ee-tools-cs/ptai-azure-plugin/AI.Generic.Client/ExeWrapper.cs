using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AI.Generic.Client {
    /// <summary>
    /// During execution of aic.exe some third-party library outputs text to standard error stream. 
    /// If Azure DevOps plugin calls aic.exe directly that build step is failed even if AST policy assessed successfully. 
    /// So we need to wrap aic.exe call and redirect error output
    /// </summary>
    public class ExeWrapper {
        protected string path;
        protected string arguments;
        public ExeWrapper(string path, string arguments) {
            this.path = path;
            this.arguments = arguments;
        }
        public int Execute() {
            int res = 1000;
            DataRead OnOutDataRead = data => Console.Write(data != null ? data : "");
            // DataRead OnErrDataRead = data => Console.Write(data != null ? "[ERROR]::" + data : "");
            DataRead OnErrDataRead = data => { }; // Ignore error output

            Thread[] readingThread = new Thread[2];
            for (int i = 0; i < readingThread.Length; i++)
                readingThread[i] = new Thread(Read);

            ProcessStartInfo info = new ProcessStartInfo() {
                WorkingDirectory = Path.GetDirectoryName(this.path),
                FileName = this.path,
                Arguments = this.arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }; 
            using (Process process = Process.Start(info)) {
                readingThread[0].Start(new StreamProcessor(process.StandardOutput, OnOutDataRead));
                readingThread[1].Start(new StreamProcessor(process.StandardError, OnErrDataRead));
                process.WaitForExit();
                res = process.ExitCode;
            }
            foreach (Thread thread in readingThread) thread.Join();

            return res;
        }

        protected delegate void DataRead(string data);

        class StreamProcessor {
            public readonly StreamReader stream;
            public readonly DataRead dataRead;
            public StreamProcessor(StreamReader stream, DataRead dataRead) {
                this.stream = stream;
                this.dataRead = dataRead;
            }
        }

        protected static void Read(object data) {
            StreamProcessor processor = data as StreamProcessor;
            // char[] buffer = new char[Console.BufferWidth];
            char[] buffer = new char[64];
            int bytesRead;
            do {
                bytesRead = processor.stream.Read(buffer, 0, buffer.Length);
                string text = bytesRead > 0 ? new string(buffer, 0, bytesRead) : null;
                processor.dataRead?.Invoke(text);
                Thread.Sleep(100);
            } while (bytesRead != 0);
        }
    }
}
