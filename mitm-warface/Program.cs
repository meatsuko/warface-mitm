using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
//using ConnectionAnalizer;

// how it work ?
// etc\hosts -> 127.0.0.1 s1.warface.ru

namespace mitm_warface
{
    class Program
    {
        static readonly TcpListener tcpListener = new TcpListener(IPAddress.Any, 5222);
        static readonly TcpListener xmppListener = new TcpListener(IPAddress.Any, 4242);

        public static Stream xmppStream;


        const int BufferSize = 4096;

        static void Main()
        {
            tcpListener.Start();
            new Task(() =>
            {
                while (true)
                {
                    var client = tcpListener.AcceptTcpClient();                    
                    new Task(() => __AcceptConnection(client)).Start();
                }
            }).Start();

            xmppListener.Start();
            new Task(() =>
            {
                while (true)
                {
                    var client = xmppListener.AcceptTcpClient();
                    Console.WriteLine("XMPP Wrapper joined!!!");

                    xmppStream = client.GetStream();

                    __readXMPP(xmppStream);
                }
            }).Start();

            Console.WriteLine("listening CryXMPP port 5222///...");
            Console.ReadLine();
            tcpListener.Stop();
        }

        public static SslStream __clientStream = null;
        public static SslStream __serverStream = null;

        private static void __AcceptConnection(TcpClient clientConnection)
        {
            Console.WriteLine("Warface XMPP Connection captured/...");

            try
            { 
                var serverConnection = new TcpClient("128.140.170.64", 5222); // ru-alpha

                NetworkStream clientStream = clientConnection.GetStream();
                NetworkStream serverStream = serverConnection.GetStream();

                byte[] buffer = new byte[4096];
                int readedBytes = 0;

                // why not Packet readed ?
                // buffer readed - 160 bytes, packet read only 148 bytes - not working
                readedBytes = clientStream.Read(buffer, 0, buffer.Length);
                serverStream.Write(buffer, 0, readedBytes);
                __debug("hello", buffer, readedBytes);


                Packet packet;

                while (true)
                {
                    packet = __readPacket(serverStream, "server");

                    string content = packet.GetContentString();

                    // попытка пропатчить TLS запрос ничего не даст, только ошибки
                    //if (content.Equals("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>WARFACE</mechanism></mechanisms></stream:features>"))
                    //{
                    //    content.Replace("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>", "");
                    //    packet.SetContentString(content);
                    //}

                    packet.Write(clientStream);
                    
                    // wait packet tls init
                    if (content.Equals("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>WARFACE</mechanism></mechanisms></stream:features>"))
                    {
                        // what is it ? 

                        // replace with Packet ?
                        // dump HEX show - magic length and nn
                        // read to end ? 
                        buffer = new byte[4096];
                        readedBytes = clientStream.Read(buffer, 0, buffer.Length);
                        serverStream.Write(buffer, 0, readedBytes);
                        __debug("tls_whtf", buffer, readedBytes);

                        continue;
                    }

                    // wait packet tls proceed
                    if (content.Equals("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
                    {
                        // tls handshake this _________


                        // this packet is last of non-crypte, break this while
                        break;
                    }
                }

                //  TEST THIS CODE
                // full tunnelign non controlled data
                //new Task(() => __Tunnel(clientStream, serverStream, "__client")).Start();
                //new Task(() => __Tunnel(serverStream, clientStream, "__server")).Start();
                //while (true) { }
                
                __clientStream = new SslStream(clientStream, true);
                //__clientStream.AuthenticateAsServer(new X509Certificate2("__cert/warface.cer", "300400"));
                __clientStream.AuthenticateAsServer(new X509Certificate("__cert/warface.cer", "300400"), false, System.Security.Authentication.SslProtocols.Tls, false);
                //проблема в момент авторизации, падает клиент (почему?)
                //может ему не нравится сертификат ? ХЗ 

                // теория - вшит сертификат в клиента ?

                // проверка *.IsAuth....() дала результат - true
                // преположительно верификация проходит успешно, но после чего КЛИЕНТ сразу ловит дисконнект
                // крашлог клиента говрит - XMPP connection lost (state 2, reason 13)
                


                __serverStream = new SslStream(serverStream, false, __sslValidationCallback, null);
                __serverStream.AuthenticateAsClient("s1.warface.ru", null, System.Security.Authentication.SslProtocols.Tls, false);

                // tls non controlled tunneling
                new Task(() => __Tunnel(__clientStream, __serverStream, "_client")).Start();
                new Task(() => __Tunnel(__serverStream, __clientStream, "_server")).Start();
                while (true) { }

                // controlled tunneling with drop data
                new Task(() =>
                {
                    while (true)
                    {
                        Packet _packet = __readPacket(__serverStream, "__server");

                        // control packet this

                        _packet.Write(__clientStream);
                    }
                }).Start();

                new Task(() =>
                {
                    while (true)
                    {
                        Packet _packet = __readPacket(__clientStream, "__client");

                        // control packet this

                        _packet.Write(__serverStream);
                    }
                }).Start();

            }
            catch(Exception exception)
            {
                Console.WriteLine(exception.Message);
            }
        }

        private static bool __sslValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors) { return true; }

        private static byte[] __MAGIC = new byte[4];
        private static Packet __readPacket(Stream stream, string nameOf)
        {
            // packet struct
            // first 12 bytes over XMPP (4x (magic, length, n/n))

            Packet packet = new Packet();

            stream.Read(packet.magic, 0, 4);
            stream.Read(packet.length, 0, 4);
            stream.Read(packet.nn, 0, 4);

            __MAGIC = packet.magic;

            packet.content = new byte[packet.GetContentLength()];

            stream.Read(packet.content, 0, packet.content.Length);

            __debug(nameOf, packet.content, packet.GetContentLength());

            return packet;
        }



        /// <summary>
        /// XMPP Scrapper
        /// for using XMPP client
        /// </summary>
        private static void __readXMPP(Stream stream)
        {
            byte[] buffer = new byte[BufferSize];

            int readedBuffer;

       
            while (true)
            {
                readedBuffer = 0;

                readedBuffer = stream.Read(buffer, 0, BufferSize);
                

                __debug("xmpp", buffer, readedBuffer);

                if (readedBuffer == 0) break;
            }
        }


        private static void __debug(String fileName, byte[] buffer, int length)
        {
            
            
            var fileInfo = new FileInfo("__debug/" + fileName + "_" + DateTime.Now.Minute + "_" + DateTime.Now.Second + "_" + DateTime.Now.Millisecond);

            if (!fileInfo.Exists)
                fileInfo.Create().Dispose();

            var fileStream = fileInfo.OpenWrite();
            fileStream.Write(buffer, 0, length);
            fileStream.Close();

            Console.Write("[" + fileName + "] ");
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(buffer, 0, length));
        }


        private static void __Tunnel(Stream inStream, Stream outStream, string nameOf)
        {
            byte[] buffer = new byte[BufferSize];

            int readedBuffer;

            while(true)
            {
                readedBuffer = 0;

                readedBuffer = inStream.Read(buffer, 0, BufferSize);
                outStream.Write(buffer, 0, readedBuffer);

                __debug(nameOf, buffer, readedBuffer);

                if (readedBuffer == 0) break;
            }
        }
    }
}
