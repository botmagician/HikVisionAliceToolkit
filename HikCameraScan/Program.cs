using System.Net;
using System.Net.Http;
using System.IO;
using System.Text;

namespace HikCameraScan
{
    internal class Program
    {
        internal delegate ScanConfig ConsoleConfigLoadFunc();
        internal delegate ScanConfig ParamConfigLoadFunc(string[] args);
        static void Main(string[] args)
        {
            string folder = "";
            bool useParamInput= false;
            for(int i=0;i< args.Length; i += 1)
            {
                if (args[i].ToLower() == "-f")
                {
                    folder = args[i+1];
                    i++;
                }else if(args[i].ToLower() == "-p")
                {
                    useParamInput = true;
                }
            }
            Dictionary<string,ConsoleConfigLoadFunc> consoleFunc=new Dictionary<string, ConsoleConfigLoadFunc> ();
            consoleFunc.Add("/doc/page/",ScanDocPageConfig.LoadFromConsole);
            consoleFunc.Add("debug", DebugTest.Test);
            consoleFunc.Add("36260scan", PoC36260Scan.LoadFromConsole);
            Dictionary<string, ParamConfigLoadFunc> paramFunc = new Dictionary<string, ParamConfigLoadFunc>();
            paramFunc.Add("/doc/page/", ScanDocPageConfig.LoadFromParam);
            //paramFunc.Add("debug", DebugTest.Test);
            paramFunc.Add("36260scan", PoC36260Scan.LoadFromParam);
            if (!useParamInput)
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
                    if (!consoleFunc.ContainsKey(configType))
                    {
                        throw new InvalidDataException(string.Format("Wrong Input:{0}", configType));
                    }
                    ScanConfig config = consoleFunc[configType]();
                    CamDetect detect = new CamDetect(config);
                    Console.Write("thread counts：");
                    int ths = Int32.Parse(Console.ReadLine());
                    List<CamDetectResult> result = detect.StartDetect(ths);

                    WriteResult(result, config, folder);
                }
                catch (InvalidDataException ex)
                {
                    Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                }
            }
            else
            {
                string? configType=null;
                int ths=4;
                for (int i = 0; i < args.Length; i += 1)
                {
                    if (args[i].ToLower().Contains("--configtype"))
                    {
                        string[] ct = args[i].Split('=');
                        if (ct.Length < 2)
                        {
                            configType = null;
                        }
                        else
                        {
                            configType = ct[1];
                        }
                    }else if (args[i].ToLower().Contains("--threads"))
                    {
                        string[] ct = args[i].Split('=');
                        if (ct.Length < 2)
                        {
                            ths = 4;
                        }
                        else
                        {
                            ths = Int32.Parse(ct[1]);
                        }
                    }
                }
                if (configType==null)
                {
                    Console.WriteLine("Wrong input");
                    return;
                }
                try
                {
                    if (!paramFunc.ContainsKey(configType))
                    {
                        throw new InvalidDataException(string.Format("Wrong Input:{0}", configType));
                    }
                    ScanConfig config = paramFunc[configType](args);
                    CamDetect detect = new CamDetect(config);
                    List<CamDetectResult> result = detect.StartDetect(ths);

                    WriteResult(result, config, folder);
                }
                catch (InvalidDataException ex)
                {
                    Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                }
            }

        }
        public static void WriteResult(List<CamDetectResult> result,ScanConfig config,string folder)
        {
            if(folder!=""||Directory.Exists(folder))
            {
                Directory.CreateDirectory(folder);
            }
            StreamWriter writer = new StreamWriter(folder+config.ResulTypeInfo+"+"+config.StartIP + "-" + config.EndIP + ".txt", false, Encoding.ASCII);
            foreach (CamDetectResult resultItem in result)
            {
                writer.WriteLine(resultItem.CamUrl+"||Port:"+resultItem.Port+"||"+resultItem.AdditionInfo);
            }
            writer.Close();
        }
        
    }
    
}
