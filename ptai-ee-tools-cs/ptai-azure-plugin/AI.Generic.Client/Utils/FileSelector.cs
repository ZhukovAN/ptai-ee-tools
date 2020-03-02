using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Utils {
    public interface FileSelector {
        /**
         * Method that each selector will implement to create their
         * selection behaviour. If there is a problem with the setup
         * of a selector, it can throw a BuildException to indicate
         * the problem.
         *
         * @param basedir A java.io.File object for the base directory
         * @param filename The name of the file to check
         * @param file A File object for this filename
         * @return whether the file should be selected or not
         * @exception BuildException if the selector was not configured correctly
         */
        bool isSelected(FileInfo basedir, String filename, FileInfo file);
    }
}
