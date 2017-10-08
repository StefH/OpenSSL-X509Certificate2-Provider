#if NETSTANDARD
using System;
using System.Security.Cryptography;
using System.Xml;
using JetBrains.Annotations;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// Based on https://gist.github.com/Jargon64/5b172c452827e15b21882f1d76a94be4
    /// </summary>
    public static class RSAExtensions
    {
        /// <summary>
        /// Initializes an System.Security.Cryptography.RSA object from the key information from an XML string.
        /// </summary>
        /// <param name="rsa">The RSA.</param>
        /// <param name="xmlString">The XML string containing System.Security.Cryptography.RSA key information.</param>
        /// <exception cref="ArgumentNullException">The RSA or xmlString is null.</exception>
        /// <exception cref="CryptographicException">The format of the xmlString parameter is not valid.</exception>
        [PublicAPI]
        public static void FromXmlString([NotNull] this RSA rsa, [NotNull] string xmlString)
        {
            if (rsa == null)
            {
                throw new ArgumentNullException(nameof(rsa));
            }

            if (xmlString == null)
            {
                throw new ArgumentNullException(nameof(xmlString));
            }

            var parameters = new RSAParameters();

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                        case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                        case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                        case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                        case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                        case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                        case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                    }
                }
            }
            else
            {
                throw new CryptographicException("The format of the xmlString parameter is not valid.");
            }

            rsa.ImportParameters(parameters);
        }

        /// <summary>
        /// Creates and returns an XML string containing the key of the current System.Security.Cryptography.RSA object.
        /// </summary>
        /// <param name="rsa">The RSACryptoServiceProvider.</param>
        /// <param name="includePrivateParameters">true to include a public and private RSA key; false to include only the public key.</param>
        /// <exception cref="ArgumentNullException">The RSA is null.</exception>
        /// <returns>An XML string containing the key of the current RSA object.</returns>
        [PublicAPI]
        public static string ToXmlString([NotNull] this RSA rsa, bool includePrivateParameters)
        {
            if (rsa == null)
            {
                throw new ArgumentNullException(nameof(rsa));
            }

            var parameters = rsa.ExportParameters(includePrivateParameters);

            string m = Convert.ToBase64String(parameters.Modulus);
            string e = Convert.ToBase64String(parameters.Exponent);
            string p = Convert.ToBase64String(parameters.P);
            string q = Convert.ToBase64String(parameters.Q);
            string dp = Convert.ToBase64String(parameters.DP);
            string dq = Convert.ToBase64String(parameters.DQ);
            string iq = Convert.ToBase64String(parameters.InverseQ);
            string d = Convert.ToBase64String(parameters.D);

            return $"<RSAKeyValue><Modulus>{m}</Modulus><Exponent>{e}</Exponent><P>{p}</P><Q>{q}</Q><DP>{dp}</DP><DQ>{dq}</DQ><InverseQ>{iq}</InverseQ><D>{d}</D></RSAKeyValue>";
        }
    }
}
#endif