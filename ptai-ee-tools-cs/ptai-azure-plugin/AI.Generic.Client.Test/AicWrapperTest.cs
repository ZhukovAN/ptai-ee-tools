using AI.Generic.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AI.Generic.Client.Test {
    [TestClass]
    public class AicWrapperTest {
        [TestMethod]
        public void testConsoleOutIntercept() {
            ExeWrapper aic = new ExeWrapper("ping.exe", "8.8.8.8 -n 10");
            int code = aic.Execute();
        }
    }
}
