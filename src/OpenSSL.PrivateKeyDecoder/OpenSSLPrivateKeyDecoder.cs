﻿using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using JetBrains.Annotations;

namespace OpenSSL.PrivateKeyDecoder
{
    /// <summary>
    /// OpenSSLPrivateKeyDecoder
    /// </summary>
    [PublicAPI]
    public sealed class OpenSSLPrivateKeyDecoder : IOpenSSLPrivateKeyDecoder
    {
        // 1.2.840.113549.1.1.1 - RSA encryption, including the sequence byte and terminal encoded null
        private readonly byte[] OIDRSAEncryption = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

        private readonly byte[] OIDpkcs5PBES2 = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
        private readonly byte[] OIDpkcs5PBKDF2 = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };

        // 1.2.840.113549.3.7 - DES-EDE3-CBC
        private readonly byte[] OIDdesEDE3CBC = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07 };

        private const string RSAPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
        private const string RSAPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
        private const string PrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        private const string PrivateKeyFooter = "-----END PRIVATE KEY-----";
        private const string PrivateEncryptedKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        private const string PrivateEncryptedKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";

        /// <inheritdoc cref="IOpenSSLPrivateKeyDecoder.Decode"/>
        public RSACryptoServiceProvider Decode([NotNull] string privateText, [CanBeNull] SecureString password = null)
        {
            if (string.IsNullOrEmpty(privateText))
            {
                throw new ArgumentNullException(nameof(privateText));
            }

            var rsaParameters = DecodeParameters(privateText, password);

            // Create RSACryptoServiceProvider instance
            var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            rsaCryptoServiceProvider.ImportParameters(rsaParameters);
            return rsaCryptoServiceProvider;
        }

        /// <inheritdoc cref="IOpenSSLPrivateKeyDecoder.DecodeParameters"/>
        public RSAParameters DecodeParameters([NotNull] string privateText, [CanBeNull] SecureString password = null)
        {
            if (string.IsNullOrEmpty(privateText))
            {
                throw new ArgumentNullException(nameof(privateText));
            }

            string text = privateText.Trim();
            if (text.StartsWith(RSAPrivateKeyHeader) && text.EndsWith(RSAPrivateKeyFooter))
            {
                byte[] data = DecoderUtils.ExtractBytes(text, RSAPrivateKeyHeader, RSAPrivateKeyFooter);
                return DecodeRSAPrivateKey(data);
            }

            if (text.StartsWith(PrivateKeyHeader) && text.EndsWith(PrivateKeyFooter))
            {
                byte[] data = DecoderUtils.ExtractBytes(text, PrivateKeyHeader, PrivateKeyFooter);
                return DecodePrivateKey(data);
            }

            if (text.StartsWith(PrivateEncryptedKeyHeader) && text.EndsWith(PrivateEncryptedKeyFooter))
            {
                throw new NotSupportedException("Not yet possible to decrypted a password protected key like : ENCRYPTED PRIVATE KEY");
            }

            throw new NotSupportedException();
        }

        private RSAParameters DecodeEncryptedPrivateKey(byte[] encpkcs8, SecureString securePassword)
        {
            var memoryStream = new MemoryStream(encpkcs8);
            using (var binr = new BinaryReader(memoryStream))
            {
                ushort twobytes = binr.ReadUInt16();
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte(); // advance 1 byte
                        break;
                    case 0x8230:
                        binr.ReadInt16(); // advance 2 bytes
                        break;
                    default:
                        return default(RSAParameters);
                }

                twobytes = binr.ReadUInt16(); // inner sequence
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte();
                        break;
                    case 0x8230:
                        binr.ReadInt16();
                        break;
                }

                byte[] seq = binr.ReadBytes(11);
                if (!DecoderUtils.CompareByteArrays(seq, OIDpkcs5PBES2)) // is it a OIDpkcs5PBES2 ?
                {
                    return default(RSAParameters);
                }

                twobytes = binr.ReadUInt16(); // inner sequence for pswd salt
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte();
                        break;
                    case 0x8230:
                        binr.ReadInt16();
                        break;
                }

                twobytes = binr.ReadUInt16(); // inner sequence for pswd salt
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte();
                        break;
                    case 0x8230:
                        binr.ReadInt16();
                        break;
                }

                seq = binr.ReadBytes(11); // read the Sequence OID
                if (!DecoderUtils.CompareByteArrays(seq, OIDpkcs5PBKDF2)) // is it a OIDpkcs5PBKDF2 ?
                {
                    return default(RSAParameters);
                }

                twobytes = binr.ReadUInt16();
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte();
                        break;
                    case 0x8230:
                        binr.ReadInt16();
                        break;
                }

                byte bt = binr.ReadByte();
                if (bt != 0x04) // expect octet string for salt
                {
                    return default(RSAParameters);
                }

                int saltsize = binr.ReadByte();
                byte[] salt = binr.ReadBytes(saltsize);

                bt = binr.ReadByte();
                if (bt != 0x02) // expect an integer for PBKF2 interation count
                {
                    return default(RSAParameters);
                }

                int itbytes = binr.ReadByte(); // PBKD2 iterations should fit in 2 bytes.
                int iterations;
                switch (itbytes)
                {
                    case 1:
                        iterations = binr.ReadByte();
                        break;
                    case 2:
                        iterations = 256 * binr.ReadByte() + binr.ReadByte();
                        break;
                    default:
                        return default(RSAParameters);
                }

                twobytes = binr.ReadUInt16();
                switch (twobytes)
                {
                    case 0x8130:
                        binr.ReadByte();
                        break;
                    case 0x8230:
                        binr.ReadInt16();
                        break;
                }

                byte[] seqdes = binr.ReadBytes(10);
                if (!DecoderUtils.CompareByteArrays(seqdes, OIDdesEDE3CBC)) // is it a OIDdes-EDE3-CBC ?
                {
                    return default(RSAParameters);
                }

                bt = binr.ReadByte();
                if (bt != 0x04) // expect octet string for IV
                {
                    return default(RSAParameters);
                }

                int ivsize = binr.ReadByte();
                byte[] IV = binr.ReadBytes(ivsize);

                bt = binr.ReadByte();
                if (bt != 0x04) // expect octet string for encrypted PKCS8 data
                {
                    return default(RSAParameters);
                }

                bt = binr.ReadByte();
                int encblobsize;
                switch (bt)
                {
                    case 0x81:
                        encblobsize = binr.ReadByte(); // data size in next byte
                        break;
                    case 0x82:
                        encblobsize = 256 * binr.ReadByte() + binr.ReadByte();
                        break;
                    default:
                        encblobsize = bt; // we already have the data size
                        break;
                }

                byte[] encryptedpkcs8 = binr.ReadBytes(encblobsize);
                byte[] pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, securePassword, iterations);
                if (pkcs8 == null) // probably a bad securePassword entered
                {
                    return default(RSAParameters);
                }

                //----- With a decrypted pkcs #8 PrivateKeyInfo blob, decode it to an RSA ---
                return DecodePrivateKey(pkcs8);
            }
        }

        /// <summary>
        /// Uses PBKD2 to derive a 3DES key and decrypts data
        /// </summary>
        private byte[] DecryptPBDK2(byte[] edata, byte[] salt, byte[] IV, SecureString securePassword, int iterations)
        {
            byte[] psbytes = SecureStringUtils.Decrypt(securePassword);

            var rfc2898DeriveBytes = new Rfc2898DeriveBytes(psbytes, salt, iterations);

            var decAlg = TripleDES.Create();
            decAlg.Key = rfc2898DeriveBytes.GetBytes(24);
            decAlg.IV = IV;

            var memoryStream = new MemoryStream();

            using (var decrypt = new CryptoStream(memoryStream, decAlg.CreateDecryptor(), CryptoStreamMode.Write))
            {
                decrypt.Write(edata, 0, edata.Length);
                decrypt.Flush();
                // decrypt.Close(); // this is REQUIRED ?
            }

            return memoryStream.ToArray();
        }

        private RSAParameters DecodePrivateKey(byte[] pkcs8)
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
                    return default(RSAParameters);
                }

                byte bt = reader.ReadByte();
                if (bt != 0x02)
                {
                    return default(RSAParameters);
                }

                twobytes = reader.ReadUInt16();
                if (twobytes != 0x0001)
                {
                    return default(RSAParameters);
                }

                byte[] seq = reader.ReadBytes(15);
                if (!DecoderUtils.CompareByteArrays(seq, OIDRSAEncryption)) // make sure Sequence for OID is correct
                {
                    return default(RSAParameters);
                }

                bt = reader.ReadByte();
                if (bt != 0x04) // expect an Octet string 
                {
                    return default(RSAParameters);
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

        private RSAParameters DecodeRSAPrivateKey(byte[] privkey)
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
                    return default(RSAParameters);
                }

                twobytes = reader.ReadUInt16();
                if (twobytes != 0x0102) // version number
                {
                    return default(RSAParameters);
                }

                byte bt = reader.ReadByte();
                if (bt != 0x00)
                {
                    return default(RSAParameters);
                }

                // All private key components are Integer sequences
                var rsaParameters = new RSAParameters();

                int elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.Modulus = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.Exponent = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.D = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.P = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.Q = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.DP = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.DQ = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.InverseQ = reader.ReadBytes(elems);

                return rsaParameters;
            }
        }    
    }
}