using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Test.Utils {
    public sealed partial class TempStorage : IDisposable {
        private TempStorage() {}

        /// <summary>
        /// Initializes a new instance of the <see cref="TempStorage"/> class.
        /// </summary>
        /// <param name="path">The path to use as temp storage.</param>
        public TempStorage(string path) {
            this.Path = path;
            this.Clear();
            this.Create();
        }

        public string Path { get; set; }

        private void Create() {
            try {
                if (!Directory.Exists(this.Path)) {
                    Directory.CreateDirectory(this.Path);
                }
            } catch (IOException) {
            }
        }

        public void Clear() {
            try {
                if (Directory.Exists(this.Path)) {
                    Directory.Delete(this.Path, true);
                }
            } catch (IOException) {
            }
        }

        /// <summary>
        /// An indicator whether this object is beeing actively disposed or not.
        /// </summary>
        private bool disposed;

        public void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Throws an exception if something is tried to be done with an already disposed object.
        /// </summary>
        /// <remarks>
        /// All public methods of the class must first call this.
        /// </remarks>
        public void ThrowIfDisposed() {
            if (this.disposed) {
                throw new ObjectDisposedException(this.GetType().Name);
            }
        }

        /// <summary>
        /// Releases managed resources upon dispose.
        /// </summary>
        /// <remarks>
        /// All managed resources must be released in this
        /// method, so after disposing this object no other
        /// object is beeing referenced by it anymore.
        /// </remarks>
        private void ReleaseManagedResources() {
            this.Clear();
        }

        /// <summary>
        /// Releases unmanaged resources upon dispose.
        /// </summary>
        /// <remarks>
        /// All unmanaged resources must be released in this
        /// method, so after disposing this object no other
        /// object is beeing referenced by it anymore.
        /// </remarks>
        private void ReleaseUnmanagedResources() {
        }

        private void Dispose(bool disposing) {
            if (!this.disposed) {
                /* Release unmanaged ressources */
                this.ReleaseUnmanagedResources();

                if (disposing) {
                    /* Release managed ressources */
                    this.ReleaseManagedResources();
                }

                /* Set indicator that this object is disposed */
                this.disposed = true;
            }
        }
    }
}
