using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class NetworkManager
    {
        public TcpClient client;
        public SslStream clientStream;
        Thread serverMessageThread;
        X509Certificate2 clientCert;
        private IPAddress IP;
        public NetworkManager(IPAddress IP, int port, X509Certificate2 clientCert)
        {
            this.client = new TcpClient();
            this.client.Connect(IP, port);
            this.clientCert = clientCert;
            this.IP = IP;
        }
        async public Task<bool> initalHandshake()
        {
            clientStream = new SslStream(this.client.GetStream(), false, (a,b,c,d)=>true);
            await clientStream.AuthenticateAsClientAsync(this.IP.ToString(), new X509CertificateCollection{clientCert}, false);
            try
            {
                await clientStream.WriteAsync(new byte[1] { 0x1 }, 0, 1);
                byte[] handShakeMessage = new byte[1024];
                await clientStream.ReadAsync(handShakeMessage, 0, handShakeMessage.Length);
                string[] Message = Encoding.UTF8.GetString(handShakeMessage).Split(":");
                if (Message[0] == "0")
                {
                    // Success
                    utils.print("Success, MOTD: " + Message[1], "Authentication");
                    return true;
                } else if (Message[0] == "1")
                {
                    // Failed
                    utils.print("Failed, Reason: " + Message[1], "Authentication");
                    return false;
                }
                return false;
            } catch (Exception ex)
            {
                utils.print("Some Errors occured: "+ex, "ErrorHandler");
                return false;
            }
        }
        public void setupReceivingThread()
        {
            serverMessageThread = new Thread(()=>_handleServerMessage(this.clientStream));
            serverMessageThread.Start();
        }
        async private void _handleServerMessage(SslStream stream)
        {
            while (true)
            {
                // Read all the available messages
                int LeftByte = -1;
                StringBuilder userMessage = new StringBuilder();
                do
                {
                    byte[] msgBuffer = new byte[1024];
                    LeftByte = await stream.ReadAsync(msgBuffer, 0, msgBuffer.Length);
                    userMessage.Append(msgBuffer);
                } while (LeftByte != 0);
                string[] Messages = userMessage.ToString().Split("<EOF>");
                // Get all the seperate message and process them, ignore the last item since I'll be empty
                for (int i = 0; i < Messages.Length - 1; i++)
                {
                    string[] IndividualMsg = Messages[i].Split("\0");
                    utils.print(IndividualMsg[1].ToString(), IndividualMsg[0]);
                }
            }
        }
    }
}
