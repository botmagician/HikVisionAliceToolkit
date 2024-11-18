using System.Net;
using System.Net.Http;
using System.IO;
using System.Text;

namespace HikCameraScan
{
    internal class Program
    {
        internal delegate ScanConfig ConsoleConfigLoadFunc();
        static void Main(string[] args)
        {
            Dictionary<string,ConsoleConfigLoadFunc> consoleFunc=new Dictionary<string, ConsoleConfigLoadFunc> ();
            consoleFunc.Add("/doc/page/",ScanDocPageConfig.LoadFromConsole);
            consoleFunc.Add("debug", DebugTest.Test);
            consoleFunc.Add("36260scan", PoC36260Scan.LoadFromConsole);
            if(args.Length == 0)
            {
                Console.WriteLine("Load config from console...");
                Console.Write("ConfigType:");
                string? configType;
                configType = Console.ReadLine();
                if (configType == null)
                {
                    Console.WriteLine("Wrong input");
                    return;
                }
                try
                {
                    if(!consoleFunc.ContainsKey(configType))
                    {
                        throw new InvalidDataException(string.Format("Wrong Input:{0}",configType));
                    }
                    ScanConfig config = consoleFunc[configType]();
                    CamDetect detect=new CamDetect(config);
                    List<CamDetectResult> result=detect.StartDetect();
                    WriteResult(result,config);
                }catch(InvalidDataException ex)
                {
                    Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                }
            }

        }
        public static void WriteResult(List<CamDetectResult> result,ScanConfig config)
        {
            StreamWriter writer = new StreamWriter(config.ResulTypeInfo+"+"+config.StartIP + "-" + config.EndIP + ".txt", false, Encoding.ASCII);
            foreach (CamDetectResult resultItem in result)
            {
                writer.WriteLine(resultItem.CamUrl+"     |Port:"+resultItem.Port+" "+resultItem.AdditionInfo);
            }
            writer.Close();
        }
    }
    
}
