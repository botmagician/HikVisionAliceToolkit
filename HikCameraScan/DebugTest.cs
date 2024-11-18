using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace HikCameraScan
{
    internal class DebugTest
    {
        public static ScanConfig Test()
        {
            var ipt=new PoC36260Interpreter();
            PoC36260Scan scan=new PoC36260Scan("10.24.25.244","10.24.25.244",ipt);
            var res = ipt.TestExist(IPAddress.Parse("10.24.25.244"), scan, new CamDetect(scan));
            Console.WriteLine(res);
            Environment.Exit(0);
            return null;
        }
    }
}
