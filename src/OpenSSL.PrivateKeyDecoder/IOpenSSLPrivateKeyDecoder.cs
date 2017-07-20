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
        /// Decode PrivateKey
        /// </summary>
        /// <param name="privateText">The private (rsa) key text.</param>
        /// <param name="securePassword">The optional password to decrypt this private key.</param>
        /// <returns>RSACryptoServiceProvider</returns>
        RSACryptoServiceProvider Decode([NotNull] string privateText, [CanBeNull] SecureString securePassword = null);
    }
}