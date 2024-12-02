using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace HikCameraScan
{
    public class CamDetect
    {
        private ScanConfig _config;
        public ScanConfig Config { get { return _config; } }
        private HttpClient _client;
        public HttpClient Client { get { return _client; } }
        public CamDetect(ScanConfig config)
        {
            _config = config;
            _client = new HttpClient(new SocketsHttpHandler() );
            _client.Timeout = TimeSpan.FromMilliseconds(4000);
        }
        public List<CamDetectResult> StartDetect(int ths)
        {
            List<CamDetectResult> result = new List<CamDetectResult>();
            List<Task<List<CamDetectResult>>> taskList = new List<Task<List<CamDetectResult>>>();

            // 获取IP地址列表
            var ipList = _config.EnumerateIPRange(_config.StartIP, _config.EndIP).ToList();
            int totalIps = ipList.Count;
            
            int chunkSize = totalIps / ths; // 每个线程处理八分之一

            // 创建8个任务，每个任务处理1/8的IP地址
            for (int i = 0; i < ths; i++)
            {
                int start = i * chunkSize;
                int end = (i == ths-1) ? totalIps : start + chunkSize;  // 最后一个线程处理剩下的IP地址

                // 创建并启动任务
                Task<List<CamDetectResult>> camTask = Task.Factory.StartNew<List<CamDetectResult>>(() =>
                {
                    List<CamDetectResult> partialResult = new List<CamDetectResult>();
                    for (int j = start; j < end; j++)
                    {
                        CamDetectResult res = _config.ContentInterpreter.CamContentDetect(ipList[j], this);
                        
                        if (res.IsCam)
                        {
                            Console.WriteLine(res.CamUrl+" "+res.Port+" "+res.AdditionInfo);
                            partialResult.Add(res);
                        }
                    }
                    return partialResult;
                });

                taskList.Add(camTask);
            }

            // 等待所有任务完成
            Task.WaitAll(taskList.ToArray());

            // 收集所有结果
            foreach (var task in taskList)
            {
                result.AddRange(task.Result);
            }

            return result;
        }
    }
    public class CamDetectResult
    {
        public IPAddress? IP { get; set; }
        public int Port {  get; set; }
        public bool IsCam { get; set; }
        public string CamUrl {  get; set; }
        public string AdditionInfo {  get; set; }
    }
}
