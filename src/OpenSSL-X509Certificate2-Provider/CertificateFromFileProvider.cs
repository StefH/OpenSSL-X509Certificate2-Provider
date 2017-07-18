using System.Security;
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
        /// <param name="securePassword">The optional securePassword to decrypt the private key.</param>
        public CertificateFromFileProvider([NotNull] string certificateText, [NotNull] string privateKeyText, [CanBeNull] SecureString securePassword = null)
        {
            Certificate = new X509Certificate2(GetPublicKeyBytes(certificateText));
#if NETSTANDARD
            PublicKey = (RSACryptoServiceProvider)Certificate.GetRSAPublicKey();
#else
            PublicKey = (RSACryptoServiceProvider)Certificate.PublicKey.Key;
#endif

            IPrivateKeyDecoder decoder = new PrivateKeyDecoder();
            PrivateKey = decoder.Decode(privateKeyText, securePassword);

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

        /// <summary>
        /// Gets the PublicKey object.
        /// </summary>
        public RSACryptoServiceProvider PublicKey { get; }
    }
}