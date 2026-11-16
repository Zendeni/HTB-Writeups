using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

internal static class StreamRunner
{
    private static readonly byte[] Key = new byte[] {
        0x31,0x9a,0x77,0xc2,0x05,0x64,0x8d,0xee,
        0x4b,0x13,0x99,0x2a,0x7f,0x40,0xbd,0x18,
        0xd1,0x56,0x0c,0xab,0x83,0x29,0xf4,0x68,
        0x72,0x35,0xe0,0x9d,0x14,0xca,0x5b,0xf1
    };

    private static readonly byte[] Iv = new byte[] {
        0x6d,0x28,0xa1,0x04,0xbb,0x73,0x9e,0x51,
        0x0f,0xc8,0x36,0x92,0xe7,0x45,0x1a,0xdc
    };

    private static byte[] Decrypt(byte[] ciphertext)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = Iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
                return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
    }

    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: StreamRunner <encrypted-assembly> <assembly-arguments...>");
            return 2;
        }

        byte[] assemblyBytes = Decrypt(File.ReadAllBytes(args[0]));
        Assembly assembly = Assembly.Load(assemblyBytes);
        MethodInfo entryPoint = assembly.EntryPoint;
        if (entryPoint == null)
            throw new InvalidOperationException("payload has no entry point");

        string[] forwarded = args.Skip(1).ToArray();
        object result = entryPoint.Invoke(null, new object[] { forwarded });
        return result is int ? (int)result : 0;
    }
}
