using System;
using System.IO;

namespace Il2CppDumper
{
    public partial class MetadataHelper
    {
        public class MT19937_64
        {
            private const ulong N = 312;
            private const ulong M = 156;
            private const ulong MATRIX_A = 0xB5026F5AA96619E9L;
            private const ulong UPPER_MASK = 0xFFFFFFFF80000000;
            private const ulong LOWER_MASK = 0X7FFFFFFFUL;
            private static ulong[] mt = new ulong[N + 1];
            private static ulong mti = N + 1;

            public MT19937_64(ulong seed)
            {
                this.Seed(seed);
            }
            public void Seed(ulong seed)
            {
                mt[0] = seed;
                for (mti = 1; mti < N; mti++)
                    mt[mti] = (6364136223846793005L * (mt[mti - 1] ^ (mt[mti - 1] >> 62)) + mti);
            }
            public ulong Int63()
            {
                ulong x = 0;
                ulong[] mag01 = new ulong[2] { 0x0UL, MATRIX_A };
                if (mti >= N)
                {
                    ulong kk;
                    if (mti == N + 1)
                        Seed(5489UL);
                    for (kk = 0; kk < (N - M); kk++)
                    {
                        x = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk + M] ^ (x >> 1) ^ mag01[x & 0x1UL];
                    }
                    for (; kk < N - 1; kk++)
                    {
                        x = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk - M] ^ (x >> 1) ^ mag01[x & 0x1UL];
                    }
                    x = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
                    mt[N - 1] = mt[M - 1] ^ (x >> 1) ^ mag01[x & 0x1UL];
                    mti = 0;
                }
                x = mt[mti++];
                x ^= (x >> 29) & 0x5555555555555555L;
                x ^= (x << 17) & 0x71D67FFFEDA60000L;
                x ^= (x << 37) & 0xFFF7EEE000000000L;
                x ^= (x >> 43);
                return x;
            }
            public ulong IntN(ulong value)
            {
                return Int63() % value;
            }
        }
        public static Stream DecryptMetadata(string metadataPath)
        {
            var data = File.ReadAllBytes(metadataPath);
            decryptMetadataBlocks(data);
            decryptMetadata(data);
            recoverMetadataHeader(data);
            var fileStream = File.Create(metadataPath + ".recoverd");
            var stream = new MemoryStream(data);
            stream.Seek(0, SeekOrigin.Begin);
            stream.CopyTo(fileStream);
            fileStream.Close();
            return stream;
        }
        private static void decryptMetadataBlocks(byte[] data)
        {
            byte[] footer = new byte[0x4000];
            Buffer.BlockCopy(data, data.Length - 0x4000, footer, 0, 0x4000);
            if (footer[0xC8] != 0x2E || footer[0xC9] != 0xFC || footer[0xCA] != 0xFE || footer[0xCB] != 0x2C)
                throw new ArgumentException("*((uint32_t*)&footer[0xC8]) != 0x2CFEFC2E");
            byte[] out1 = new byte[0x10];
            byte[] out2 = new byte[0xB00];
            ushort offset = (ushort)((footer[0xD3] << 8) | footer[0xD2]);
            Buffer.BlockCopy(footer, offset, out1, 0, 0x10);
            Buffer.BlockCopy(footer, offset + 0x10, out2, 0, 0xB00);
            for (int i = 0; i < 0x10; i++)
                out1[i] ^= footer[0x3000 + i];
            for (int i = 0; i < 0xB00; i++)
                out2[i] ^= (byte)(footer[0x3010 + i] ^ out1[i % 0x10]);
            byte[] key = new byte[0xB0];
            for (int i = 0; i < 0xB00; i++)
                key[i / 0x10] ^= out2[i];
            byte[] tmp1 = new byte[0x10];
            byte[] tmp2 = new byte[0x10];
            var size = (data.Length / 0x100) / 0x40 * 0x40;
            for (int i = 0; i < 0x100 * size; i += size)
            {
                for (int j = 0; j < 0x10; j++)
                    tmp1[j] = (byte)(out1[j] ^ _p0[j]);
                for (int j = 0; j < 0x40; j += 0x10)
                {
                    Buffer.BlockCopy(tmp1, 0, tmp2, 0, 0x10);
                    Buffer.BlockCopy(data, i + j, tmp1, 0, 0x10);
                    decryptMetadataBlocks16Bytes(key, data, i + j);
                    for (int k = 0; k < 0x10; k++)
                        data[i + j + k] ^= tmp2[k];
                }
            }
        }
        private static void decryptMetadataBlocks16Bytes(byte[] key, byte[] data, int offset)
        {
            for (int i = 0; i < 0x10; i++)
                data[i + offset] ^= key[i];
            uint[] tmp1 = new uint[4];
            byte[] tmp2 = new byte[0x10];
            for (int i = 1; i < 10; i++)
            {
                for (int j = 0; j < 4; j++)
                    tmp1[j] = 0;
                for (int j = 0; j < 4; j++)
                {
                    tmp1[j] ^= _p2[data[_p1[4 * j + 0] + offset]];
                    tmp1[j] ^= _p3[data[_p1[4 * j + 1] + offset]];
                    tmp1[j] ^= _p4[data[_p1[4 * j + 2] + offset]];
                    tmp1[j] ^= _p5[data[_p1[4 * j + 3] + offset]];
                }
                Buffer.BlockCopy(tmp1, 0, tmp2, 0, tmp2.Length);
                for (int j = 0; j < 0x10; j++)
                    data[j + offset] = (byte)(tmp2[j] ^ key[0x10 * i + j]);
            }
            for (int i = 0; i < 0x10; i++)
            {
                byte b = data[_p1[i] + offset];
                tmp2[i] = (byte)(_p6[b] ^ ~b);
            }
            for (int i = 0; i < 0x10; i++)
                data[i + offset] = (byte)(tmp2[i] ^ key[0xA0 + i]);
        }
        private static void decryptMetadata(byte[] data)
        {
            var tables = new uint[0x12];
            Buffer.BlockCopy(data, 0x60, tables, 0, 16);
            Buffer.BlockCopy(data, 0x140, tables, 16, 16);
            Buffer.BlockCopy(data, 0x100, tables, 32, 16);
            Buffer.BlockCopy(data, 0xF0, tables, 48, 8);
            Buffer.BlockCopy(data, 0x8, tables, 56, 16);
            ulong temp = ((ulong)tables[tables[0] & 0xF] << 32) | tables[(tables[0x11] & 0xF) + 2];
            var rand = new MT19937_64(temp);
            decryptMetadataHeaderXor(data, 0xDC, (uint)rand.Int63()); // stringCount
            decryptMetadataHeaderXor(data, 0xD8, (uint)rand.Int63()); // stringOffset
            rand.Int63();
            decryptMetadataHeaderXor(data, 0x20, (uint)rand.Int63()); // stringLiteralOffset
            decryptMetadataHeaderXor(data, 0x1C, (uint)rand.Int63()); // stringLiteralDataCount
            decryptMetadataHeaderXor(data, 0x18, (uint)rand.Int63()); // stringLiteralDataOffset
            var key = new byte[0x5000];
            for (int i = 0; i < 0x5000; i += 8)
            {
                temp = rand.Int63();
                key[i] = (byte)(temp);
                key[i + 1] = (byte)(temp >> 8);
                key[i + 2] = (byte)(temp >> 16);
                key[i + 3] = (byte)(temp >> 24);
                key[i + 4] = (byte)(temp >> 32);
                key[i + 5] = (byte)(temp >> 40);
                key[i + 6] = (byte)(temp >> 48);
                key[i + 7] = (byte)(temp >> 56);
            }
            decryptMetadataStringLiteral(data, key);
        }
        private static void decryptMetadataHeaderXor(byte[] data, int offset, uint xor)
        {
            for (int i = 0; i < 4; i++)
                data[i + offset] ^= (byte)(xor >> (i * 8)); // Little-Endian
        }
        private static void decryptMetadataStringLiteral(byte[] data, byte[] key)
        {
            var stringLiteralDesc = new int[4];
            Buffer.BlockCopy(data, 0x18, stringLiteralDesc, 0, 0x10);
            var stringLiteralDataOffset = stringLiteralDesc[0];
            var stringLiteralDataCount = stringLiteralDesc[1];
            var stringLiteralOffset = stringLiteralDesc[2];
            var stringLiteralCount = stringLiteralDesc[3];
            var stringLiterals = new ulong[stringLiteralCount / 8];
            Buffer.BlockCopy(data, stringLiteralOffset, stringLiterals, 0, stringLiteralCount);
            int offset, length;
            for (int i = 0; i < stringLiterals.Length; i++)
            {
                offset = (int)(stringLiterals[i]) + stringLiteralDataOffset;
                length = (int)(stringLiterals[i] >> 32);
                for (int j = 0; j < length; j++)
                    data[j + offset] ^= (byte)(key[(0x1400 + j) % 0x5000] ^ (key[i % 0x2800 + j % 0x2800] + (byte)j));
            }
        }
        private static void recoverMetadataHeader(byte[] data)
        {
            // sanity == 0xFAB11BAF
            data[0] = 0xAF;
            data[1] = 0x1B;
            data[2] = 0xB1;
            data[3] = 0xFA;
            // version == 24
            data[4] = 24;
            data[5] = 0;
            data[6] = 0;
            data[7] = 0;
        }
    }
}
