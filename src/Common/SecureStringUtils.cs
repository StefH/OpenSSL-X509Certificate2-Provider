using System;
using System.Runtime.InteropServices;
using System.Security;
using JetBrains.Annotations;

namespace OpenSSL.Common
{
    /// <summary>
    /// SecureString Utility methods
    /// </summary>
    public static class SecureStringUtils
    {
        /// <summary>
        /// Converts a string to a SecureString.
        /// </summary>
        /// <param name="input">The string to encrypt.</param>
        /// <returns>SecureString</returns>
        public static SecureString Encrypt(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            var secure = new SecureString();
            foreach (char c in input)
            {
                secure.AppendChar(c);
            }

            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// Decrypt a securestring into a byte array.
        /// </summary>
        /// <param name="secure">The SecureString.</param>
        /// <returns>byte[]</returns>
        public static byte[] Decrypt([NotNull] SecureString secure)
        {
            if (secure == null)
            {
                throw new ArgumentNullException(nameof(secure));
            }

            byte[] passwordData = new byte[secure.Length];

            IntPtr unmanagedPassword = IntPtr.Zero;
            try
            {
#if NETSTANDARD
                unmanagedPassword = SecureStringMarshal.SecureStringToGlobalAllocAnsi(secure);
#else
                unmanagedPassword = Marshal.SecureStringToGlobalAllocAnsi(secure);
#endif
                Marshal.Copy(unmanagedPassword, passwordData, 0, passwordData.Length);
            }
            finally
            {
                if (unmanagedPassword != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPassword);
                }
            }

            return passwordData;
        }
    }
}