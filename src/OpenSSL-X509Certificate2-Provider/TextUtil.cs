using System;

namespace OpenSSL.X509Certificate2Provider
{
    internal static class TextUtil
    {
        internal static byte[] ExtractBytes(string text, string header, string footer)
        {
            string data = text;
            data = data.Replace(header, string.Empty);
            data = data.Replace(footer, string.Empty);

            return Convert.FromBase64String(data);
        }
    }
}