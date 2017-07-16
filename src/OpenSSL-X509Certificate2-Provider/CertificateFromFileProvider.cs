using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// CertificateFromFileProvider
    /// </summary>
    [PublicAPI]
    public class CertificateFromFileProvider : BaseCertificateProvider, ICertificateProvider
    {
        /// <summary>
        /// CertificateFromFileProvider
        /// </summary>
        /// <param name="certificateText">The certificate or public key text.</param>
        /// <param name="privateKeyText">The private (rsa) key text.</param>
        public CertificateFromFileProvider([NotNull] string certificateText, [NotNull] string privateKeyText)
        {
            Certificate = new X509Certificate2(GetPublicKeyBytes(certificateText));
            PrivateKey = DecodePrivateKey(privateKeyText);

#if !NETSTANDARD
            Certificate.PrivateKey = PrivateKey;
#endif
        }

        /// <summary>
        /// Gets the generated X509Certificate2 object.
        /// </summary>
        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// Gets the PrivateKey object.
        /// </summary>
        public RSACryptoServiceProvider PrivateKey { get; }
    }
}