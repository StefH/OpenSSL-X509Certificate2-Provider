using JetBrains.Annotations;
using System.Security.Cryptography;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// IPrivateKeyDecoder
    /// </summary>
    public interface IPrivateKeyDecoder
    {
        /// <summary>
        /// Decode PrivateKey
        /// </summary>
        /// <param name="privateText">The private (rsa) key text.</param>
        /// <returns>RSACryptoServiceProvider</returns>
        RSACryptoServiceProvider Decode([NotNull] string privateText);
    }
}