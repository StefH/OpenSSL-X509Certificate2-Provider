using System;
using System.IO;

namespace OpenSSL.PrivateKeyDecoder
{
    internal static class DecoderUtils
    {
        internal static bool CompareByteArrays(byte[] arrayA, byte[] arrayB)
        {          
            if (arrayA.Length != arrayB.Length)
            {
                return false;
            }

            int i = 0;
            foreach (var c in arrayA)
            {
                if (c != arrayB[i])
                {
                    return false;
                }
                i++;
            }

            return true;
        }

        internal static byte[] ExtractBytes(string text, string header, string footer)
        {
            string data = text;
            data = data.Replace(header, string.Empty);
            data = data.Replace(footer, string.Empty);

            return Convert.FromBase64String(data);
        }

        internal static int GetFieldLength(BinaryReader reader)
        {
            byte bt = reader.ReadByte();

            if (bt <= 0x80)
            {
                //when the value is less than 0x80, then it is a direct length.
                return bt;
            }

            //when 0x8? is specified, the value after the 8 is the number of bytes to read for the length
            //we are going to assume up to 4 bytes since anything bigger is ridiculous, and 4 translates nicely to an integer

            //.net is litte endian, whereas asn.1 is big endian, so just fill the array backwards.

            int bytesToRead = bt & 0x0F;
            byte[] lengthArray = new byte[4];

            for (var i = 4 - bytesToRead; i < 4; i++)
            {
                lengthArray[4 - i - 1] = reader.ReadByte();
            }

            return BitConverter.ToInt32(lengthArray, 0);
        }

        internal static int GetIntegerSize(BinaryReader reader)
        {
            byte bt = reader.ReadByte();
            if (bt != 0x02) // expect integer
            {
                return 0;
            }

            int count = GetFieldLength(reader);

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