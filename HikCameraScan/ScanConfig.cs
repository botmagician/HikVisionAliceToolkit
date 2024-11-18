using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace HikCameraScan
{
    public class ScanConfig
    {
        protected string _startIP;
        protected string _endIP;
        protected string _scanUri;
        protected IContentInterpreter _contentInterpreter;
        protected string _resulTypeInfo;
        public string StartIP
        {
            get { return _startIP; }
        }
        public string EndIP
        {
            get { return _endIP; }
        }
        public string ScanUri
        {
            get { return _scanUri; }
        }
        public IContentInterpreter ContentInterpreter
        {
            get { return _contentInterpreter; }
        }
        public string ResulTypeInfo
        {
            get { return _resulTypeInfo; }
        }
        public virtual IEnumerable<IPAddress> EnumerateIPRange(string startIP, string endIP)
        {
            var start = IPAddress.Parse(startIP).GetAddressBytes();
            var end = IPAddress.Parse(endIP).GetAddressBytes();

            Array.Reverse(start);  // Convert to big-endian
            Array.Reverse(end);    // Convert to big-endian

            uint startValue = BitConverter.ToUInt32(start, 0);
            uint endValue = BitConverter.ToUInt32(end, 0);
            List<IPAddress> result = new List<IPAddress>();
            for (uint current = startValue; current <= endValue; current++)
            {
                byte[] bytes = BitConverter.GetBytes(current);
                Array.Reverse(bytes); // Convert back to little-endian for display
                result.Add(new IPAddress(bytes));
            }
            return result;
        }
        protected ScanConfig(string startIP, string endIP, string scanUri, IContentInterpreter interpreter)
        {
            _startIP = startIP;
            _endIP = endIP;
            _scanUri = scanUri;
            _contentInterpreter = interpreter;
        }
    }
}
