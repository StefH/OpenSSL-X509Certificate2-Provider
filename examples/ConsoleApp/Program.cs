using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using OpenSSL.X509Certificate2Provider;

namespace ConsoleApp
{
    static class Program
    {
        static void Main(string[] args)
        {
            // Generated using:
            // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate_pub.crt
            string certificateText = File.ReadAllText("certificate_pub.crt");
            string privateKeyText = File.ReadAllText("private.key");

            ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText);
            X509Certificate2 certificate = provider.Certificate;

            Console.WriteLine("X509Certificate2:");
            Console.WriteLine(certificate);
            Console.WriteLine();
            Console.WriteLine("PrivateKey:");
            RSACryptoServiceProvider cryptoServiceProvider = (RSACryptoServiceProvider)certificate.PrivateKey;
            ShowRSAProperties(cryptoServiceProvider);

            var xml = XDocument.Parse(cryptoServiceProvider.ToXmlString(true));
            Console.WriteLine(xml.ToString());

            // Sign the data
            byte[] hello = new UTF8Encoding().GetBytes("Hello World");
            byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

            RSACryptoServiceProvider publicKey = provider.PublicKey;
            bool verifyHashResult = publicKey.VerifyData(hello, CryptoConfig.MapNameToOID("SHA256"), hashValue);
            Console.WriteLine();
            Console.WriteLine("VerifyHash: {0}", verifyHashResult);
        }

        private static void ShowRSAProperties(RSACryptoServiceProvider rsa)
        {
            Console.WriteLine("RSA CSP key information:");

            CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
            Console.WriteLine("Accessible property: " + keyInfo.Accessible);
            try
            {
                Console.WriteLine("Exportable property: {0}", keyInfo.Exportable);
            }
            catch
            {
                Console.WriteLine("Exportable property: N/A");
            }
            Console.WriteLine("HardwareDevice property: " + keyInfo.HardwareDevice);
            Console.WriteLine("KeyContainerName property: " + keyInfo.KeyContainerName);
            Console.WriteLine("KeyNumber property: " + keyInfo.KeyNumber);
            Console.WriteLine("MachineKeyStore property: " + keyInfo.MachineKeyStore);
            Console.WriteLine("Protected property: " + keyInfo.Protected);
            Console.WriteLine("ProviderName property: " + keyInfo.ProviderName);
            Console.WriteLine("ProviderType property: " + keyInfo.ProviderType);
            Console.WriteLine("RandomlyGenerated property: " + keyInfo.RandomlyGenerated);
            Console.WriteLine("Removable property: " + keyInfo.Removable);
            Console.WriteLine("UniqueKeyContainerName property: " + keyInfo.UniqueKeyContainerName);
        }
    }
}