using JetBrains.Annotations;
using System.Security.Cryptography;

namespace OpenSSL.X509Certificate2Provider
{
    public interface IPrivateKeyDecoder
    {
        RSACryptoServiceProvider Decode([NotNull] string privateText);
    }
}