using System;
using System.IO;
using System.Net.Security;

namespace mitm_warface
{
    class Packet
    {
        public byte[] magic = new byte[4];
        public byte[] length = new byte[4];
        public byte[] nn = new byte[4];

        public byte[] content;

        public int GetContentLength()
        {
            return BitConverter.ToInt32(length, 0);
        }

        public Packet Write(Stream stream)
        {
            stream.Write(magic, 0, 4);
            stream.Write(BitConverter.GetBytes(content.Length), 0, 4);
            stream.Write(nn, 0, 4);
            stream.Write(content, 0, content.Length);
            stream.Flush();

            return this;
        }

        public String GetContentString()
        {
            return System.Text.Encoding.UTF8.GetString(content);
        }

        public Packet WriteContent(Stream stream)
        {
            stream.Write(content, 0, content.Length);

            return this;
        }

        public Packet SetContentString(string join)
        {
            content = System.Text.Encoding.UTF8.GetBytes(join);

            return this;
        }
    }
}
