using System;
using System.IO;
using System.Security.Cryptography;
using JetBrains.Annotations;

namespace OpenSSL.X509Certificate2Provider
{
    /// <summary>
    /// BaseCertificateProvider to parse OpenSSL public and private key components. Based on http://www.jensign.com/opensslkey/opensslkey.cs
    /// </summary>
    public abstract class BaseCertificateProvider
    {
        // encoded OID sequence for PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1", including the sequence byte and terminal encoded null
        private readonly byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

        private const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
        private const string PublicKeyFooter = "-----END PUBLIC KEY-----";
        private const string PublicCertificateHeader = "-----BEGIN CERTIFICATE-----";
        private const string PublicCertificateFooter = "-----END CERTIFICATE-----";
        private const string RSAPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private const string RSAPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
        private const string PrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        private const string PrivateKeyFooter = "-----END PRIVATE KEY-----";

        /// <summary>
        /// GetPublicKeyBytes
        /// </summary>
        /// <param name="publicText">The certificate or public key text.</param>
        /// <returns>byte array</returns>
        protected byte[] GetPublicKeyBytes([NotNull] string publicText)
        {
            string text = publicText.Trim();
            if (text.StartsWith(PublicKeyHeader) && text.EndsWith(PublicKeyFooter))
            {
                return ExtractBytes(text, PublicKeyHeader, PublicKeyFooter);
            }

            if (text.StartsWith(PublicCertificateHeader) && text.EndsWith(PublicCertificateFooter))
            {
                return ExtractBytes(text, PublicCertificateHeader, PublicCertificateFooter);
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// DecodePrivateKey
        /// </summary>
        /// <param name="privateText">The private (rsa) key text.</param>
        /// <returns>RSACryptoServiceProvider</returns>
        protected RSACryptoServiceProvider DecodePrivateKey([NotNull] string privateText)
        {
            string text = privateText.Trim();
            if (text.StartsWith(RSAPrivateKeyHeader) && text.EndsWith(RSAPrivateKeyFooter))
            {
                byte[] data = ExtractBytes(text, RSAPrivateKeyHeader, RSAPrivateKeyFooter);
                return DecodeRSAPrivateKey(data);
            }

            if (text.StartsWith(PrivateKeyHeader) && text.EndsWith(PrivateKeyFooter))
            {
                byte[] data = ExtractBytes(text, PrivateKeyHeader, PrivateKeyFooter);
                return DecodePrivateKey(data);
            }

            throw new NotSupportedException();
        }

        private byte[] ExtractBytes(string text, string header, string footer)
        {
            string data = text;
            data = data.Replace(header, string.Empty);
            data = data.Replace(footer, string.Empty);

            return Convert.FromBase64String(data);
        }

        private RSACryptoServiceProvider DecodePrivateKey(byte[] pkcs8)
        {
            // read the asn.1 encoded SubjectPublicKeyInfo blob
            var memoryStream = new MemoryStream(pkcs8);
            int streamLength = (int)memoryStream.Length;

            using (var reader = new BinaryReader(memoryStream))
            {
                ushort twobytes = reader.ReadUInt16();
                if (twobytes == 0x8130) // data read as little endian order (actual data order for Sequence is 30 81)
                {
                    reader.ReadByte(); // advance 1 byte
                }
                else if (twobytes == 0x8230)
                {
                    reader.ReadInt16(); // advance 2 bytes
                }
                else
                {
                    return null;
                }

                byte bt = reader.ReadByte();
                if (bt != 0x02)
                {
                    return null;
                }

                twobytes = reader.ReadUInt16();
                if (twobytes != 0x0001)
                {
                    return null;
                }

                byte[] seq = reader.ReadBytes(15);
                if (!CompareByteArrays(seq, SeqOID)) // make sure Sequence for OID is correct
                {
                    return null;
                }

                bt = reader.ReadByte();
                if (bt != 0x04) // expect an Octet string 
                {
                    return null;
                }

                bt = reader.ReadByte(); // read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                if (bt == 0x81)
                {
                    reader.ReadByte();
                }
                else if (bt == 0x82)
                {
                    reader.ReadUInt16();
                }

                // at this stage, the remaining sequence should be the RSA private key
                byte[] rsaprivkey = reader.ReadBytes((int)(streamLength - memoryStream.Position));
                return DecodeRSAPrivateKey(rsaprivkey);
            }
        }

        private RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            // decode the asn.1 encoded RSA private key
            var memoryStream = new MemoryStream(privkey);
            using (var reader = new BinaryReader(memoryStream))
            {
                ushort twobytes = reader.ReadUInt16();
                if (twobytes == 0x8130) // data read as little endian order (actual data order for Sequence is 30 81)
                {
                    reader.ReadByte(); // advance 1 byte
                }
                else if (twobytes == 0x8230)
                {
                    reader.ReadInt16(); // advance 2 bytes
                }
                else
                {
                    return null;
                }

                twobytes = reader.ReadUInt16();
                if (twobytes != 0x0102) // version number
                {
                    return null;
                }

                byte bt = reader.ReadByte();
                if (bt != 0x00)
                {
                    return null;
                }

                // all private key components are Integer sequences
                var rsaParameters = new RSAParameters();

                int elems = GetIntegerSize(reader);
                rsaParameters.Modulus = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.Exponent = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.D = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.P = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.Q = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.DP = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.DQ = reader.ReadBytes(elems);

                elems = GetIntegerSize(reader);
                rsaParameters.InverseQ = reader.ReadBytes(elems);

                // create RSACryptoServiceProvider instance
                var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                rsaCryptoServiceProvider.ImportParameters(rsaParameters);
                return rsaCryptoServiceProvider;
            }
        }

        private bool CompareByteArrays(byte[] arrayA, byte[] arrayB)
        {
            if (arrayA.Length != arrayB.Length)
            {
                return false;
            }

            int i = 0;
            foreach (byte c in arrayA)
            {
                if (c != arrayB[i])
                {
                    return false;
                }
                i++;
            }

            return true;
        }

        private int GetIntegerSize(BinaryReader reader)
        {
            int count;
            byte bt = reader.ReadByte();
            if (bt != 0x02) // expect integer
            {
                return 0;
            }
            bt = reader.ReadByte();

            switch (bt)
            {
                case 0x81:
                    count = reader.ReadByte(); // data size in next byte
                    break;
                case 0x82:
                    byte highbyte = reader.ReadByte();
                    byte lowbyte = reader.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                    break;
                default:
                    count = bt; // we already have the data size
                    break;
            }

            while (reader.ReadByte() == 0x00)
            {
                // remove high order zeros in data
                count -= 1;
            }

            reader.BaseStream.Seek(-1, SeekOrigin.Current); // last ReadByte wasn't arrayA removed zero, so back up arrayA byte
            return count;
        }
    }
}