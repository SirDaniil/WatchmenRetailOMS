using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web.Script.Serialization;
using BlackyPaw.Crypto;
using Jose;

namespace Auth
{
    internal class ObtainToken
    {
        private string key;
        private string hostname;

        public static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
                return;
            
            var obtain = new ObtainToken();

            for (int i = 0; i < args.Length; i++)
                switch (args[i])
                {
                    case "-key":
                        obtain.setKey(args[++i]);
                        break;

                    case "-hostname":
                        obtain.setHostname(args[++i]);
                        break;
                }

            Console.WriteLine(obtain.obtainAccessToken());
        }

        private void setHostname(string hostname)
        {
            if (hostname == null || (hostname = hostname.Trim()).Length == 0)
                throw new Exception("Missing hostname");

            if (hostname[hostname.Length - 1] == '/')
                hostname = hostname.Substring(0, hostname.Length - 1);

            if (!hostname.StartsWith("http://") && !hostname.StartsWith("https://"))
                hostname = "https://" + hostname;

            this.hostname = hostname;
        }

        private void setKey(string key)
        {
            this.key = key;
        }

        /// <summary>
        /// Generates the request token
        /// </summary>
        /// <returns></returns>
        private string generateToken()
        {
            var filename = key + ".pem";
            var pos = filename.LastIndexOf('.');
            var accessKey = filename.Substring(0, pos);

            // Get public key
            var publicKey = File.ReadAllText(filename);
            publicKey = publicKey.Replace("\n", "");
            publicKey = publicKey.Replace("\r", "");
            publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "");
            publicKey = publicKey.Replace("-----END PUBLIC KEY-----", "");
            var publicKeyBytes = Convert.FromBase64String(publicKey);
            
            // Read and understand the key
            var ms = new MemoryStream(publicKeyBytes);
            var importer = X509EncodedPublicKeyImporter.ImportFromDER(ms);
            var rsaKey = ((RSAPublicKeyImporter)importer).ToCngKey();
            
            // Generate the request
            var payload = new Dictionary<string, object>()
            {
                { "iss" , "Sample in .net" },
                { "exp", DateTimeOffset.Now.ToUnixTimeSeconds() + 10 },
                { "iat" , DateTimeOffset.Now.ToUnixTimeSeconds() },
                { "jti" , Guid.NewGuid().ToString() }
            };
            
            var headers = new Dictionary<string, object>();
            headers.Add("kid", accessKey);

            // Encrypt it
            return JWT.Encode(payload, rsaKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, extraHeaders: headers);
        }

        /// <summary>
        /// Obtains access token.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private string obtainAccessToken()
        {
            // Get the request token
            var request = new TokenRequest();
            request.jwe = generateToken();

            // Convert to json
            var jss = new JavaScriptSerializer();
            var json = jss.Serialize(request);
            
            // Send token request
            var req = (HttpWebRequest)WebRequest.Create(hostname + "/api/v1/oms/token");
            req.ContentType = "application/json";
            req.Method = "POST";
            req.Timeout = 60 * 1000;
            req.ReadWriteTimeout = 60 * 1000;

            using (var sw = new StreamWriter(req.GetRequestStream()))
            {
                sw.Write(json);
                sw.Flush();
            }

            // Get the response
            var response = (HttpWebResponse)req.GetResponse();
            var stream = response.GetResponseStream();
            if (stream == null)
                throw new Exception("Nothing was returned");
            
            using (var sr = new StreamReader(stream))
            {
                var result = sr.ReadToEnd();
                var resp = jss.Deserialize<BasicResponse>(result);
                
                if (!resp.success)
                    throw new Exception("Token count not be obtained: " + resp.content);
                    
                return resp.content;
            }
        }
    }
}