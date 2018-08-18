using OpenSSL.X509Certificate2Provider;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HTTPClientCertDownload
{
    class Program
    {
        static void Main(string[] args)
        {
            // openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out crt.pem
            string certificateText = File.ReadAllText("crt.pem");
            string privateKeyText = File.ReadAllText("key.pem");

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            ServicePointManager.DefaultConnectionLimit = 9999;

            // Ignore Server Certificate validation
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(@"https://server.cryptomix.com/secure/");
            req.PreAuthenticate = true;

            ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText, true);

#if NETCOREAPP2_0
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.rsacertificateextensions.copywithprivatekey?redirectedfrom=MSDN&view=netcore-2.0#System_Security_Cryptography_X509Certificates_RSACertificateExtensions_CopyWithPrivateKey_System_Security_Cryptography_X509Certificates_X509Certificate2_System_Security_Cryptography_RSA_
            X509Certificate2 certificate = RSACertificateExtensions.CopyWithPrivateKey(provider.Certificate, provider.PrivateKey);
#else
            X509Certificate2 certificate = provider.Certificate;
#endif
            req.ClientCertificates.Add(certificate);

            HttpWebResponse response = (HttpWebResponse)req.GetResponse();

            var encoding = Encoding.ASCII;
            using (var reader = new StreamReader(response.GetResponseStream(), encoding))
            {
                string responseText = reader.ReadToEnd();
                Console.WriteLine(responseText);
            }
        }
    }
}