using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace HikCameraScan
{

    public interface IContentInterpreter
    {
        public bool TestExist(IPAddress ip,ScanConfig config,CamDetect detector);
        public CamDetectResult CamContentDetect(IPAddress ip, CamDetect detector);
    }
}
