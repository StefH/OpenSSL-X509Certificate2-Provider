using System.Security;
using JetBrains.Annotations;
using System.Security.Cryptography;

namespace OpenSSL.PrivateKeyDecoder
{
    /// <summary>
    /// IOpenSSLPrivateKeyDecoder
    /// </summary>
    public interface IOpenSSLPrivateKeyDecoder
    {
        /// <summary>
        /// Decode PrivateKey into a RSACryptoServiceProvider object. (Windows only)
        /// </summary>
        /// <param name="privateText">The private (rsa) key text.</param>
        /// <param name="securePassword">The optional password to decrypt this private key.</param>
        /// <returns>RSACryptoServiceProvider</returns>
        [PublicAPI]
        RSACryptoServiceProvider Decode([NotNull] string privateText, [CanBeNull] SecureString securePassword = null);

        /// <summary>
        /// Decode PrivateKey into a RSAParameters struct.
        /// </summary>
        /// <param name="privateText">The private text.</param>
        /// <param name="securePassword">The secure password.</param>
        /// <returns>RSAParameters</returns>
        [PublicAPI]
        RSAParameters DecodeParameters([NotNull] string privateText, [CanBeNull] SecureString securePassword = null);
    }
}