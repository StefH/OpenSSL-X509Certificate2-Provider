using System.Security;
using JetBrains.Annotations;
using System.Security.Cryptography;

namespace OpenSSL.PublicKeyDecoder
{
    /// <summary>
    /// IOpenSSLPublicKeyDecoder
    /// </summary>
    public interface IOpenSSLPublicKeyDecoder
    {
        /// <summary>
        /// Decode Public Key into a RSACryptoServiceProvider object. (Windows only)
        /// </summary>
        /// <param name="publicText">The public (rsa) key text.</param>
        /// <returns>RSACryptoServiceProvider</returns>
        RSACryptoServiceProvider Decode([NotNull] string publicText);

        /// <summary>
        /// Decode Public Key into a RSAParameters struct.
        /// </summary>
        /// <param name="publicText">The public text.</param>        
        /// <returns>RSAParameters</returns>
        RSAParameters DecodeParameters([NotNull] string publicText);
    }
}