using LastPass;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace LastPassCrack
{   
    public static class Tools
    {  
        public static TextWriter ConsoleOut;

        public static Vault GetVault(string username, string password, string sxml)
        {
            var decryptData = Tools.GetDataFromSxmlFile(sxml);
            decryptData.key = FetcherHelper.MakeKey(username, password, decryptData.iterations);
            var result = Tools.Decrypt(decryptData);
            var blob = new Blob(Convert.FromBase64String(result.Substring(5)), decryptData.iterations);
            return new Vault(blob, decryptData.key);
        }

        public static DecryptData GetDataFromSlpsFile(string content)
        {
            var parts = content.Split('\n');
            if (parts.Length < 2)
            {
                content = Unprotect(content);
                parts = content.Split('\n');
            }
            var lastPassRocks = parts[1];
            var firstPart = parts[0];
            return new DecryptData
            {
                data = lastPassRocks,
                mode = Mode.ECB,
                b64 = true,
                iterations = 5000
            };
        }

        public static string Unprotect(string data)
        {
            var bytes = Convert.FromBase64String(data);
            var unprotected = ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine);
            var i = unprotected.Length - 1;
            while (unprotected[i] == 0) i--;
            var withoutZeros = new byte[i+1];
            Array.Copy(unprotected, withoutZeros, i + 1);
            return withoutZeros.ToUtf8();
        }

        public static DecryptData GetDataFromSxmlFile(string content)
        {
            var parts = content.Split(';');
            if (parts.Length < 2) 
            {
                content = Unprotect(content);
                parts = content.Split(';');
            }
            var iterationsPart = parts[0].Split('=');
            var result = new DecryptData
            {
                data = parts[1],
                b64 = true,
                iterations = int.Parse(iterationsPart[1])
            };
            parts = parts[1].Split('|');
            if(parts.Length < 2)
            {
                result.mode = Mode.ECB;
            }
            else
            {
                result.data = parts[1];
                result.mode = Mode.CBC;
                result.iv = Convert.FromBase64String(parts[0].Substring(1));
            }
            return result;
        }

        public static byte[][] ExpandKey(byte[] key)
        {
            var foursCount = key.Length / 4;
            var totalCount = foursCount + 6;
            var fours = new byte[(totalCount + 1) * 4][];
            int i;
            for (i = 0; i < foursCount; i++)
            {
                var four = new byte[4]{ key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3] };
                fours[i] = four;
            }
            for (; i < 4 * (totalCount + 1); i++)
            {
                var intermediateResult = new byte[4];
                var previousFour = fours[i - 1];
                if (i % foursCount == 0)
                {
                    var newFour = new byte[4];
                    newFour[0] = previousFour[1];
                    newFour[1] = previousFour[2];
                    newFour[2] = previousFour[3];
                    newFour[3] = previousFour[0];
                    var substitutions = newFour.Select(_ => DumbList_1[_]).ToArray();
                    var xorred = new byte[4];
                    for (int j = 0; j < 4; j++)
                        xorred[j] = (byte)(substitutions[j] ^ DumbListOfFours_1[i / foursCount][j]);
                    intermediateResult = xorred;
                }
                else if (foursCount > 6 && i % foursCount == 4)
                {
                    for (int k = 0; k < previousFour.Length; k++ )
                        intermediateResult[k] = DumbList_1[previousFour[k]];
                }
                else
                {
                    intermediateResult = previousFour;
                }
                var newFourResult = new byte[4];
                for (int k = 0; k < 4; k++)
                    newFourResult[k] = (byte)(fours[i - foursCount][k] ^ intermediateResult[k]);
                fours[i] = newFourResult;
            }
            return fours;
        }

        public static PreparedData Prepare(DecryptData data)
        {
            var preparedData = new PreparedData
            {
                data = StringToPaddedData(data.data),
                mode = data.mode,
                b64 = data.b64,
                iv = data.iv,
            };
            if (data.mode == Mode.CBC)
                preparedData.key = data.key;
            else
            {
                if (data.key != null)
                    preparedData.key = data.key;
                else
                    preparedData.key = StringToKey(data.password, 256);

            }
            preparedData.round = ExpandKey(preparedData.key);
            return preparedData;
            
        }

        public static byte[] StringToKey(string letters, int bits)
        {
            var keyLength = bits / 8;
            var lettersLength = letters.Length;
            var result = new byte[32];
            var index = 0;
            for(int i=0; i<keyLength; i++)
            {
                if (index == lettersLength) index = 0;
                result[i] = (byte)letters[index];
                index++;
            }
            return result;
        }

        public static byte[] BytesToKey(byte[] bytes, int bits)
        {
            var keyLength = bits / 8;
            var lettersLength = bytes.Length;
            var result = new byte[32];
            var index = 0;
            for (int i = 0; i < keyLength; i++)
            {
                if (index == lettersLength) index = 0;
                result[i] = bytes[index];
                index++;
            }
            return result;
        }
                
        public static string Decrypt(DecryptData data)
        {
            var preparedData = Prepare(data);
            if (data.b64) preparedData.data = Convert.FromBase64String(data.data);
            var decryptedData = new byte[preparedData.data.Length];
            var xor = preparedData.iv;
            var previousSixteen = new byte[16];
            for(int i=0; i<preparedData.data.Length / 16; i++)
            {
                if (i > 0 && preparedData.mode == Mode.CBC)
                {
                    Array.Copy(previousSixteen, xor, 16);
                }
                Array.Copy(preparedData.data, i * 16, previousSixteen, 0, 16);
                var decryptedSixteen = InvCipher(previousSixteen, preparedData.round);
                if (data.mode == Mode.CBC)
                    for (int k = 0; k < 16; k++)
                    {
                        decryptedSixteen[k] = (byte)(decryptedSixteen[k] ^ xor[k]);
                    }
                Array.Copy(decryptedSixteen, 0, decryptedData, i * 16, 16);
            }
            return PaddedDataToString(decryptedData);
        }

        public static byte[][] ShiftAndXor(byte[][] block)
        {
            for (int j = 0; j < 4; j++)
            {
                var xor_3_2_1 = new List<int>();
                var xor_3_1_c = new List<int>();
                var xor_3_2_c = new List<int>();
                var xor_3_c = new List<int>();

                for (int k = 0; k < 4; k++)
                {
                    var current = block[k][j];
                    var shifted_1 = current << 1;
                    if (shifted_1 > 255) shifted_1 ^= 283;
                    var shifted_2 = shifted_1 << 1;
                    if (shifted_2 > 255) shifted_2 ^= 283;
                    var shifted_3 = shifted_2 << 1;
                    if (shifted_3 > 255) shifted_3 ^= 283;

                    xor_3_2_1.Add(shifted_3 ^ shifted_2 ^ shifted_1);
                    xor_3_1_c.Add(shifted_3 ^ shifted_1 ^ current);
                    xor_3_2_c.Add(shifted_3 ^ shifted_2 ^ current);
                    xor_3_c.Add(shifted_3 ^ current);
                }
                block[0][j] = (byte)(xor_3_2_1[0] ^ xor_3_1_c[1] ^ xor_3_2_c[2] ^ xor_3_c[3]);
                block[1][j] = (byte)(xor_3_2_1[1] ^ xor_3_1_c[2] ^ xor_3_2_c[3] ^ xor_3_c[0]);
                block[2][j] = (byte)(xor_3_2_1[2] ^ xor_3_1_c[3] ^ xor_3_2_c[0] ^ xor_3_c[1]);
                block[3][j] = (byte)(xor_3_2_1[3] ^ xor_3_1_c[0] ^ xor_3_2_c[1] ^ xor_3_c[2]);
            }
            return block;
        }

        public static byte[] InvCipher(byte[] block16, byte[][] key)
        {
            var block4x4  = Make4x4(block16);
            var xorred = Xor(block4x4, key.Length / 4 - 1, key);
            for (int i = key.Length / 4 - 2; i > 0; i--)
            {
                block4x4 = ChangeOrder(block4x4, (index, subIndex) => (subIndex + (4 - index)) % 4);
                block4x4 = SubstituteForNumberAtIndex(block4x4, DumbList_2);
                block4x4 = Xor(block4x4, i, key);
                block4x4 = ShiftAndXor(block4x4);
                               
            }
            block4x4 = ChangeOrder(block4x4, (index, subIndex) => (subIndex + (4 - index)) % 4);
            block4x4 = SubstituteForNumberAtIndex(block4x4, DumbList_2);
            block4x4 = Xor(block4x4, 0, key);
            var result = new byte[16];
            for (int i = 0; i < 4; i++ )
            {
                for(int j=0; j<4; j++)
                {
                    result[i + 4 * j] = block4x4[i][j];
                }
            }
            return result;
        }

        public static byte[][] Xor(byte[][] block, int keyIndexMultiplier, byte[][] key)
        {
            for(int i=0; i<4; i++)
            {
                for(int j=0; j<4; j++)
                {
                    block[i][j] ^= key[keyIndexMultiplier*4 + j][i];
                }
            }
            return block;
        }

        public static byte[][] ChangeOrder(byte[][] block, Func<int, int, int> orderFunction)
        {
            var result = new byte[4][];
            result[0] = block[0];
            for(int i=1; i<4; i++)
            {
                var resultRow = new byte[4];
                for(int j=0; j<4; j++)
                {
                    resultRow[j] = block[i][orderFunction(i, j)];
                }
                result[i] = resultRow;
            }
            return result;
        }

        public static byte[][] SubstituteForNumberAtIndex(byte[][] block, byte[] substitutionList)
        {
            for(int i=0; i<4; i++)
            {
                for(int j=0; j<4; j++)
                {
                    block[i][j] = substitutionList[block[i][j]];
                }
            }
            return block;
        }

        public static byte[][] Make4x4(byte[] block)
        {
            var result = new byte[4][];
            for (int i=0; i<4; i++)
            {
                var resultRow = new byte[4];
                for (int j=0; j<4; j++)
                {
                    resultRow[j] = block[i + 4 * j];
                }
                result[i] = resultRow;
            }
            return result;
        }

        public static byte[] StringToPaddedData(string input)
        {
            var bytes = input.Select(_ => (byte)_).ToArray();
            var paddingCount = 16 - (bytes.Count() % 16);
            var padding = Enumerable.Repeat(paddingCount, paddingCount).Select(_ => (byte)_).ToArray();
            var result = new byte[bytes.Length + padding.Length];
            bytes.CopyTo(result, 0);
            padding.CopyTo(result, bytes.Length);
            return result;
        }

        public static string PaddedDataToString(byte[] data)
        {
            var last = data.Last();
            if (last >= 0 && last <= 16)
            {
                var dataWithoutPadding = new byte[data.Length - last];
                Array.Copy(data, dataWithoutPadding, data.Length - last);
                return System.Text.Encoding.UTF8.GetString(dataWithoutPadding);
            }
            else 
            {
                return string.Empty;
            }
        }

       

        public static List<int> GetCharcodes(string input)
        {
            var bytes = Encoding.ASCII.GetBytes(input);
            var charcodes = bytes.Select(x => (int)x);
            return charcodes.ToList();
        }

        public static List<int> GetKey(List<int> passwordCharacterCodes)
        {
            var characterCodes = passwordCharacterCodes.ToList();
            var max = 32;
            var count = characterCodes.Count();
            if (count >= max)
                return characterCodes.GetRange(0, max);
            var counter = 0;
            var index = 0;
            var key = new List<int>();
            while(counter < max)
            {
                key.Add(characterCodes[index]);
                counter++;
                index++;
                if (index == count)
                    index = 0;
            }
            return key;
        }

        //public static List<List<int>> ExpandKey(List<int> input)
        //{
        //    var key = input.ToList();
        //    var foursCount = key.Count / 4;
        //    var totalCount = foursCount + 6;
        //    var fours = new List<List<int>>();
        //    int i;
        //    for (i = 0; i < foursCount; i++)
        //    {
        //        var subList = new List<int> { key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3] };
        //        fours.Add(subList);
        //    }
        //    for (; i < 4 * (totalCount + 1); i++)
        //    {
        //        List<int> intermediateResult;
        //        var previousFour = fours[i - 1];
        //        if (i % foursCount == 0)
        //        {
        //            var newFour = previousFour.GetRange(1, 3);
        //            newFour.Add(previousFour[0]);
        //            var substitutions = newFour.Select(_ => DumbList_1[_]).ToList();
        //            var xorred = new List<int>();
        //            for (int j=0; j<4; j++)
        //                xorred.Add(substitutions[j] ^ DumbListOfFours_1[i/foursCount][j]);
        //            intermediateResult = xorred;
        //        }
        //        else if (foursCount > 6 && i % foursCount == 4)
        //        {
        //            intermediateResult = previousFour.Select(_ => DumbList_1[_]).ToList();
        //        }
        //        else
        //        {
        //            intermediateResult = previousFour;
        //        }
        //        var newFourResult = new List<int>();
        //        for (int k = 0; k < 4; k++)
        //            newFourResult.Add(fours[i - foursCount][k] ^ intermediateResult[k]);
        //        fours.Add(newFourResult);
        //    }
        //    return fours;
        //}

        public static List<byte> DumbList_1 = new List<byte> 
        {
            99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 
            118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 
            164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 
            241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 
            226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 
            179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 
            57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 
            127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 
            218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 
            126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 
            184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 
            172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 
            86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 
            221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 
            53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 
            155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 
            65, 153, 45, 15, 176, 84, 187, 22
        };

        public static byte[] DumbList_2 = new byte[]
        {
            82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 
            227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 
            148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 
            40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 
            104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 
            185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 
            10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 
            189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 
            240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 
            117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 
            190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 
            244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 
            127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 
            77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 
            119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
        };

        public static byte[][] DumbListOfFours_1 = new byte[][]
        {
            new byte[]{0, 0, 0, 0},
            new byte[]{1, 0, 0, 0},
            new byte[]{2, 0, 0, 0},
            new byte[]{4, 0, 0, 0},
            new byte[]{8, 0, 0, 0},
            new byte[]{16, 0, 0, 0},
            new byte[]{32, 0, 0, 0},
            new byte[]{64, 0, 0, 0},
            new byte[]{128, 0, 0, 0},
            new byte[]{27, 0, 0, 0},
            new byte[]{54, 0, 0, 0}
        };
    }

    public enum Mode { CBC, ECB };

    public struct DecryptData
    {
        public byte[] key;
        public byte[] iv;
        public string data;
        public bool b64;
        public int bits;
        public Mode mode;
        public int iterations;
        public string password;
    }

    public struct PreparedData
    {
        public byte[] key;
        public byte[] iv;
        public byte[] data;
        public bool b64;
        public int bits;
        public Mode mode;
        public byte[][] round;
    }
}
