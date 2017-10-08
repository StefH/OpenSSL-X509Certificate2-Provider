using System;
using JetBrains.Annotations;
using OpenSSL.PrivateKeyDecoder;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// BaseCertificateProvider to parse OpenSSL public and private key components. Based on http://www.jensign.com/opensslkey/opensslkey.cs
    /// </summary>
    public abstract class BaseCertificateProvider
    {
        private const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
        private const string PublicKeyFooter = "-----END PUBLIC KEY-----";
        private const string PublicCertificateHeader = "-----BEGIN CERTIFICATE-----";
        private const string PublicCertificateFooter = "-----END CERTIFICATE-----";

        /// <summary>
        /// GetPublicKeyBytes
        /// </summary>
        /// <param name="publicText">The certificate or public key text.</param>
        /// <returns>byte array</returns>
        protected byte[] GetPublicKeyBytes([NotNull] string publicText)
        {
            if (publicText == null)
            {
                throw new ArgumentNullException(nameof(publicText));
            }

            string text = publicText.Trim();
            if (text.StartsWith(PublicKeyHeader) && text.EndsWith(PublicKeyFooter))
            {
                return TextUtil.ExtractBytes(text, PublicKeyHeader, PublicKeyFooter);
            }

            if (text.StartsWith(PublicCertificateHeader) && text.EndsWith(PublicCertificateFooter))
            {
                return TextUtil.ExtractBytes(text, PublicCertificateHeader, PublicCertificateFooter);
            }

            throw new NotSupportedException();
        }
    }
}