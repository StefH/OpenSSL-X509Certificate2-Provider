using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// ICertificateProvider
    /// </summary>
    public interface ICertificateProvider
    {
        /// <summary>
        /// Gets the generated X509Certificate2 object.
        /// </summary>
        X509Certificate2 Certificate { get; }

        /// <summary>
        /// Gets the PrivateKey
        /// </summary>
        RSACryptoServiceProvider PrivateKey { get; }
    }
}