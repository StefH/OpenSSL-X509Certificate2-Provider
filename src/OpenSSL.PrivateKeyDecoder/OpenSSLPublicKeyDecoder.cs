using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using JetBrains.Annotations;
using OpenSSL.PrivateKeyDecoder;

namespace OpenSSL.PublicKeyDecoder
{
    /// <summary>
    /// OpenSSLPublicKeyDecoder
    /// </summary>
    [PublicAPI]
    public sealed class OpenSSLPublicKeyDecoder : IOpenSSLPublicKeyDecoder
    {
        // 1.2.840.113549.1.1.1 - RSA encryption, including the sequence byte and terminal encoded null
        private readonly byte[] OIDRSAEncryption = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };


        private const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
        private const string PublicKeyFooter = "-----END PUBLIC KEY-----";

        /// <inheritdoc cref="IOpenSSLPublicKeyDecoder.Decode"/>
        public RSACryptoServiceProvider Decode([NotNull] string publicText)
        {
            if (string.IsNullOrEmpty(publicText))
            {
                throw new ArgumentNullException(nameof(publicText));
            }
            var rsaParameters = DecodeParameters(publicText);

            // Create RSACryptoServiceProvider instance
            var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            rsaCryptoServiceProvider.ImportParameters(rsaParameters);
            return rsaCryptoServiceProvider;
        }

        /// <inheritdoc cref="IOpenSSLPublicKeyDecoder.DecodeParameters"/>
        public RSAParameters DecodeParameters([NotNull] string publicText)
        {
            if (string.IsNullOrEmpty(publicText))
            {
                throw new ArgumentNullException(nameof(publicText));
            }

            string text = publicText.Trim();
            if (text.StartsWith(PublicKeyHeader) && text.EndsWith(PublicKeyFooter))
            {
                byte[] data = DecoderUtils.ExtractBytes(text, PublicKeyHeader, PublicKeyFooter);
                return DecodePublicKey(data);
            }

            throw new NotSupportedException();
        }

        private RSAParameters DecodePublicKey(byte[] pkcs8)
        {
            // read the asn.1 encoded SubjectPublicKeyInfo blob
            var memoryStream = new MemoryStream(pkcs8);

            using (var reader = new BinaryReader(memoryStream))
            {
                //read the data type
                reader.ReadByte();
                
                //read the field length
                DecoderUtils.GetFieldLength(reader);

                byte[] seq = reader.ReadBytes(15);
                if (!DecoderUtils.CompareByteArrays(seq, OIDRSAEncryption)) // make sure Sequence for OID is correct
                {
                    return default(RSAParameters);
                }

                byte bt = reader.ReadByte();
                if (bt != 0x03) // expect a bit string
                {
                    return default(RSAParameters);
                }

                //read the bitstream length
                DecoderUtils.GetFieldLength(reader);
                bt = reader.ReadByte();
                if (bt != 0x00) // expect a zero for number of bits in the bitstring that are unused
                {
                    return default(RSAParameters);
                }

                byte dateType = reader.ReadByte();
                if (dateType != 0x30) // data read as little endian order (actual data order for Sequence is 30 81)
                {
                    return default(RSAParameters);
                }

                //read the sequence length
                DecoderUtils.GetFieldLength(reader);

                var rsaParameters = new RSAParameters();

                int elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.Modulus = reader.ReadBytes(elems);

                elems = DecoderUtils.GetIntegerSize(reader);
                rsaParameters.Exponent = reader.ReadBytes(elems);

                return rsaParameters;
            }
        }
    }
}