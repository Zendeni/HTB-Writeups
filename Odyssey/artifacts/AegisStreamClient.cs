using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

internal static class AegisStreamClient
{
    private const uint Magic = 0xA3915EAB;

    private sealed class Frame
    {
        public uint RequestId;
        public string OpCode = "";
        public byte[] Payload = new byte[0];
        public byte[] Signature = new byte[32];
    }

    private static byte[] Concat(byte[] left, byte[] right)
    {
        byte[] result = new byte[left.Length + right.Length];
        Buffer.BlockCopy(left, 0, result, 0, left.Length);
        Buffer.BlockCopy(right, 0, result, left.Length, right.Length);
        return result;
    }

    private static byte[] Sign(byte[] key, string opCode, byte[] payload)
    {
        using (HMACSHA256 hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(Concat(Encoding.UTF8.GetBytes(opCode), payload));
        }
    }

    private static void WriteFrame(Stream stream, Frame frame)
    {
        byte[] op = Encoding.UTF8.GetBytes(frame.OpCode);
        using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
        {
            writer.Write(Magic);
            writer.Write(frame.RequestId);
            writer.Write((ushort)op.Length);
            writer.Write(op);
            writer.Write((uint)frame.Payload.Length);
            writer.Write(frame.Payload);
            writer.Write(frame.Signature);
            writer.Flush();
        }
    }

    private static byte[] ReadExact(BinaryReader reader, int length)
    {
        byte[] result = reader.ReadBytes(length);
        if (result.Length != length)
            throw new EndOfStreamException("short named-pipe response");
        return result;
    }

    private static Frame ReadFrame(Stream stream)
    {
        using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
        {
            uint magic = reader.ReadUInt32();
            if (magic != Magic)
                throw new InvalidDataException("bad response magic");
            Frame frame = new Frame();
            frame.RequestId = reader.ReadUInt32();
            ushort opLength = reader.ReadUInt16();
            frame.OpCode = Encoding.UTF8.GetString(ReadExact(reader, opLength));
            uint payloadLength = reader.ReadUInt32();
            if (payloadLength > 10485760)
                throw new InvalidDataException("response too large");
            frame.Payload = ReadExact(reader, (int)payloadLength);
            frame.Signature = ReadExact(reader, 32);
            return frame;
        }
    }

    private static int Main(string[] args)
    {
        if (args.Length != 5 || args[0] != "request")
        {
            Console.Error.WriteLine("usage: AegisStreamClient request <key-file> <opcode> <payload-file-or-dash> <output-file>");
            return 2;
        }

        byte[] key = File.ReadAllBytes(args[1]);
        byte[] payload = args[3] == "-" ? new byte[0] : File.ReadAllBytes(args[3]);
        Frame request = new Frame();
        request.RequestId = 1;
        request.OpCode = args[2];
        request.Payload = payload;
        request.Signature = Sign(key, request.OpCode, request.Payload);

        using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", "AegisStreamMgmt", PipeDirection.InOut))
        {
            pipe.Connect(5000);
            WriteFrame(pipe, request);
            Frame response = ReadFrame(pipe);
            Console.WriteLine("status=" + response.OpCode + " bytes=" + response.Payload.Length);
            File.WriteAllBytes(args[4], response.Payload);
            return response.OpCode == "OK" ? 0 : 1;
        }
    }
}
