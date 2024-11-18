using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.NetworkInformation;

namespace HikCameraScan
{
    
    public class ScanDocPageConfig :ScanConfig
    {
        public static ScanDocPageConfig LoadFromConsole()
        {
            string? startIP,endIP;
            Console.WriteLine("Config type:/doc/page/login.asp");
            Console.Write("Start IP:");
            startIP=Console.ReadLine();
            Console.Write("End IP:");
            endIP = Console.ReadLine();
            if(startIP==null || endIP == null)
            {
                Console.WriteLine("Wrong input!");
                throw new InvalidDataException("Null data");
            }
            return new ScanDocPageConfig(startIP,endIP,new ScanDocPageInterpreter());
        }
        public ScanDocPageConfig(string startIP,string endIP,IContentInterpreter interpreter):base(startIP,endIP,"/doc/page/login.asp",interpreter)
        {
            _resulTypeInfo = "DocPageExist";
        }
        
    }
    public class ScanDocPageInterpreter :IContentInterpreter
    {
        public bool TestExist(IPAddress ip, ScanConfig config, CamDetect detector)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingOptions options = new PingOptions
                    {
                        DontFragment = true
                    };

                    string data = "ping_test_data";
                    byte[] buffer = System.Text.Encoding.ASCII.GetBytes(data);
                    int timeout = 10; // 1 second timeout for each packet

                    int successfulPings = 0;
                    for (int i = 0; i < 2; i++)
                    {
                        PingReply reply = ping.Send(ip, timeout, buffer, options);
                        if (reply.Status == IPStatus.Success)
                        {
                            successfulPings++;
                        }
                    }

                    return successfulPings > 0;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
        public CamDetectResult CamContentDetect(IPAddress ip, CamDetect detector)
        {
            try
            {
                bool exist=this.TestExist(ip,detector.Config, detector);
                if(!exist)throw new Exception();
                var resp = detector.Client.GetAsync("http://" + ip.ToString() + detector.Config.ScanUri).Result;
                if (!resp.IsSuccessStatusCode)
                {
                    return new CamDetectResult() { IP = ip, Port = 80, IsCam = false };
                }
                else
                {
                    var content = resp.Content.ReadAsStringAsync().Result;
                    /*
                    var htmlDoc = new HtmlDocument();
                    htmlDoc.LoadHtml(content);
                    var footerNode = htmlDoc.DocumentNode.SelectSingleNode("//div[@class='footer' and @id='footer']");
                    if (footerNode != null && footerNode.InnerText.Contains("Hikvision Digital Technology Co., Ltd."))
                    {
                        var yearMatch = System.Text.RegularExpressions.Regex.Match(footerNode.InnerText, "©(\\d{4})");
                        if (yearMatch.Success)
                        {
                            Console.WriteLine("http://" + ip.ToString() + detector.Config.ScanUri);
                            return new CamDetectResult() { IP = ip, Port = 80, IsCam = true ,CamUrl= "http://" + ip.ToString() + detector.Config.ScanUri };
                        }
                    }
                    */
                    if (content.Contains("login"))
                    {
                        Console.WriteLine("http://" + ip.ToString() + detector.Config.ScanUri);
                        return new CamDetectResult() { IP = ip, Port = 80, IsCam = true, CamUrl = "http://" + ip.ToString() + detector.Config.ScanUri ,AdditionInfo = ""};
                    }
                    return new CamDetectResult() { IP = ip, Port = 80, IsCam = false };
                }
            }
            catch (Exception)
            {
                return new CamDetectResult() { IP = null, Port = 80, IsCam = false };
            }
        }
    }
}
