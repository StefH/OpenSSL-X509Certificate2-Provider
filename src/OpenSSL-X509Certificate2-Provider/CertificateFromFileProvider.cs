using JetBrains.Annotations;
using OpenSSL.PrivateKeyDecoder;
using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// CertificateFromFileProvider
    /// </summary>
    [PublicAPI]
    public class CertificateFromFileProvider : BaseCertificateProvider, ICertificateProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateFromFileProvider"/> class.
        /// </summary>
        /// <param name="certificateText">The certificate or public key text.</param>
        /// <param name="privateKeyText">The private (rsa) key text.</param>
        /// <param name="securePassword">The optional securePassword to decrypt the private key.</param>
        public CertificateFromFileProvider([NotNull] string certificateText, [NotNull] string privateKeyText, [NotNull] SecureString securePassword) :
            this(certificateText, privateKeyText, false, securePassword)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateFromFileProvider"/> class.
        /// </summary>
        /// <param name="certificateText">The certificate or public key text.</param>
        /// <param name="privateKeyText">The private (rsa) key text.</param>
        /// <param name="useKeyContainer">Store the private key in a key container. <see href="https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container" /></param>
        /// <param name="securePassword">The optional securePassword to decrypt the private key.</param>
        /// <exception cref="ArgumentNullException">certificateText or privateKeyText</exception>
        public CertificateFromFileProvider([NotNull] string certificateText, [NotNull] string privateKeyText, bool useKeyContainer = false, [CanBeNull] SecureString securePassword = null)
        {
            if (certificateText == null)
            {
                throw new ArgumentNullException(nameof(certificateText));
            }

            if (privateKeyText == null)
            {
                throw new ArgumentNullException(nameof(privateKeyText));
            }

            Certificate = new X509Certificate2(GetPublicKeyBytes(certificateText));
#if NETSTANDARD
            PublicKey = Certificate.GetRSAPublicKey();
#else
            PublicKey = (RSACryptoServiceProvider)Certificate.PublicKey.Key;
#endif

            IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
            var privateKey = decoder.Decode(privateKeyText, securePassword);

            if (useKeyContainer)
            {
                var cspParameters = new CspParameters { KeyContainerName = $"{{{Guid.NewGuid()}}}" };
                var cspPrivateKey = new RSACryptoServiceProvider(cspParameters);
                cspPrivateKey.ImportParameters(privateKey.ExportParameters(true));
                PrivateKey = cspPrivateKey;
            }
            else
            {
                PrivateKey = privateKey;
            }

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
#if NETSTANDARD
        public RSA PublicKey { get; }
#else
        public RSACryptoServiceProvider PublicKey { get; }
#endif
    }
}