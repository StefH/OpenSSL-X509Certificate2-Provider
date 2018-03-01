using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using OpenSSL.PrivateKeyDecoder;
using OpenSSL.PublicKeyDecoder;
using OpenSSL.X509Certificate2Provider;

namespace ConsoleAppNetCore
{
    public static class Demo
    {
        public static void TestX509Certificate2()
        {
            Console.WriteLine("TestX509Certificate2");

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
            RSACryptoServiceProvider cryptoServiceProvider = provider.PrivateKey;
            ShowRSAProperties(cryptoServiceProvider);

            var xml = XDocument.Parse(RSAExtensions.ToXmlString(cryptoServiceProvider, true));
            Console.WriteLine(xml.ToString());

            // Sign the data
            byte[] hello = new UTF8Encoding().GetBytes("Hello World");
            byte[] hashValue = cryptoServiceProvider.Encrypt(hello, false);

            // var publicKey = provider.PublicKey;
            byte[] decrypted = cryptoServiceProvider.Decrypt(hashValue, false);
            Console.WriteLine("decrypted: {0}", Encoding.UTF8.GetString(decrypted));
        }

        //public static void TestX509Certificate2WithRsa()
        //{
        //    Console.WriteLine("TestX509Certificate2WithRSA");

        //    // Generated using:
        //    // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate_pub.crt
        //    string certificateText = File.ReadAllText("certificate_pub.crt");
        //    string privateKeyText = File.ReadAllText("private_rsa.key");

        //    ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText);
        //    X509Certificate2 certificate = provider.Certificate;

        //    Console.WriteLine("X509Certificate2:");
        //    Console.WriteLine(certificate);
        //    Console.WriteLine();
        //    Console.WriteLine("PrivateKey:");
        //    RSACryptoServiceProvider cryptoServiceProvider = (RSACryptoServiceProvider)certificate.PrivateKey;
        //    ShowRSAProperties(cryptoServiceProvider);

        //    var xml = XDocument.Parse(cryptoServiceProvider.ToXmlString(true));
        //    Console.WriteLine(xml.ToString());

        //    // Sign the data
        //    byte[] hello = new UTF8Encoding().GetBytes("Hello World");
        //    byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

        //    RSACryptoServiceProvider publicKey = provider.PublicKey;
        //    bool verifyHashResult = publicKey.VerifyData(hello, CryptoConfig.MapNameToOID("SHA256"), hashValue);
        //    Console.WriteLine();
        //    Console.WriteLine("VerifyHash: {0}", verifyHashResult);
        //}

        //public static void TestX509Certificate2WithEncryptedPrivateKey()
        //{
        //    Console.WriteLine("TestX509Certificate2WithEncryptedPrivateKey");

        //    // Generated using:
        //    // openssl req -x509 -sha256 -days 365 -newkey rsa:2048 -keyout pwd_private_temp.key -out pwd_certificate_pub.crt
        //    // openssl pkcs8 -topk8 -in pwd_private_temp.key -out pwd_private.key
        //    // password = abc123
        //    string certificateText = File.ReadAllText("pwd_certificate_pub.crt");
        //    string privateKeyText = File.ReadAllText("pwd_private.key");

        //    ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText, SecureStringUtils.Encrypt("abc123"));
        //    X509Certificate2 certificate = provider.Certificate;

        //    Console.WriteLine("X509Certificate2:");
        //    Console.WriteLine(certificate);
        //    Console.WriteLine();
        //    Console.WriteLine("PrivateKey:");
        //    RSACryptoServiceProvider cryptoServiceProvider = (RSACryptoServiceProvider)certificate.PrivateKey;
        //    ShowRSAProperties(cryptoServiceProvider);

        //    var xml = XDocument.Parse(cryptoServiceProvider.ToXmlString(true));
        //    Console.WriteLine(xml.ToString());

        //    // Sign the data
        //    byte[] hello = new UTF8Encoding().GetBytes("Hello World");
        //    byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

        //    RSACryptoServiceProvider publicKey = provider.PublicKey;
        //    bool verifyHashResult = publicKey.VerifyData(hello, CryptoConfig.MapNameToOID("SHA256"), hashValue);
        //    Console.WriteLine();
        //    Console.WriteLine("VerifyHash: {0}", verifyHashResult);
        //}

        public static void TestPrivateKey()
        {
            Console.WriteLine("TestPrivateKey");

            string privateKeyText = File.ReadAllText("private.key");

            IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
            RSACryptoServiceProvider cryptoServiceProvider = decoder.Decode(privateKeyText);

            // Sign the data
            byte[] hello = new UTF8Encoding().GetBytes("Hello World");
            // byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

            // ShowBytes("hashValue", hashValue);
        }

        public static void TestPublicKey()
        {
            Console.WriteLine("TestPublicKey");

            //load the public key for testing.
            string publicKeyText = File.ReadAllText("public.key");
            IOpenSSLPublicKeyDecoder publicKeyDecoder = new OpenSSLPublicKeyDecoder();
            RSACryptoServiceProvider publicKeyCsp = publicKeyDecoder.Decode(publicKeyText);
            var publicParameters = publicKeyCsp.ExportParameters(false);

            //load the corresponding private key that matches the public key
            //to verify that the parameters match
            string privateKeyText = File.ReadAllText("private.key");
            IOpenSSLPrivateKeyDecoder privateKeyDecoder = new OpenSSLPrivateKeyDecoder();
            RSACryptoServiceProvider privateKeyCsp = privateKeyDecoder.Decode(privateKeyText);
            var privateParameters = privateKeyCsp.ExportParameters(false);

            if (!publicParameters.Modulus.SequenceEqual(privateParameters.Modulus)
                || !publicParameters.Exponent.SequenceEqual(privateParameters.Exponent))
            {
                throw new Exception("public.key does not match private.key");
            }
        }

        //public static void TestPrivateRsaKey()
        //{
        //    Console.WriteLine("TestPrivateRsaKey");

        //    string privateKeyText = File.ReadAllText("private_rsa.key");

        //    IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
        //    RSACryptoServiceProvider cryptoServiceProvider = decoder.Decode(privateKeyText);

        //    // Sign the data
        //    byte[] hello = new UTF8Encoding().GetBytes("Hello World RSA");
        //    byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

        //    ShowBytes("hashValue", hashValue);
        //}

        private static void ShowBytes(string info, byte[] data)
        {
            Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
            for (int i = 1; i <= data.Length; i++)
            {
                Console.Write("{0:X2}  ", data[i - 1]);
                if (i % 16 == 0)
                {
                    Console.WriteLine();
                }
            }
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
