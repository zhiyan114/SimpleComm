using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Server
{
    public class NetworkManager
    {
        private TcpListener server;
        private X509Certificate2 serverCert;
        private config conf;
        public List<TcpClient> ChatClient = new List<TcpClient>();
        public List<TcpClient> FileClient = new List<TcpClient>(); // Future Implementation

        private Thread listenThread;

        private Dictionary<TcpClient, SslStream> ChatClientStream = new Dictionary<TcpClient, SslStream>();
        private Dictionary<TcpClient, Thread> ChatClientThread = new Dictionary<TcpClient, Thread>();
        public NetworkManager(config conf, string certPass)
        {
            this.serverCert = new X509Certificate2(conf.serverCertName, certPass);
            this.conf = conf;
            server = new TcpListener(IPAddress.Parse(conf.IP), conf.Port);
            server.Start();
        }




        public void setupListenThread()
        {
            listenThread = new Thread(() => _listenThread());
            listenThread.Start();
        }
        async private void _listenThread()
        {
            while(true)
            {
                TcpClient unauthCli = await server.AcceptTcpClientAsync();
                // Perform inital authentication check
                SslStream unauthStream = new SslStream(unauthCli.GetStream(), false);
                try
                {
                    await unauthStream.AuthenticateAsServerAsync(this.serverCert, true, true);
                    
                    if (unauthStream.RemoteCertificate == null) { await _rejectClient(unauthCli, unauthStream, "Certificate is required to authenticate you"); return; }
                    X509Certificate2 cliCert = new X509Certificate2(unauthStream.RemoteCertificate);
                    // CA Verify
                    X509Chain certChain = new X509Chain();
                    certChain.Build(cliCert);
                    bool isCASponsored = false;
                    foreach (X509ChainElement cert in certChain.ChainElements)
                        isCASponsored = Array.Find<string>(this.conf.CAFingerprint, (a)=>a.ToLower() == cert.Certificate.Thumbprint.ToLower()) != null;
                    if(!isCASponsored) { await _rejectClient(unauthCli, unauthStream, "Certificate is not issued by an authorized CA"); return; }

                    // Check if the client has been blacklisted
                    if (Array.Find<string>(this.conf.BannedSerial, (k) => k.ToLower().Equals(cliCert.SerialNumber.ToLower())) != null)
                    {
                        await _rejectClient(unauthCli, unauthStream, "Certificate Serial Blacklisted");
                        return;
                    }

                    // Get client type request
                    byte[] req = new byte[1];
                    await unauthStream.ReadAsync(req, 0, req.Length);

                    List<X509EnhancedKeyUsageExtension> KeyUsages = cliCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
                    switch (req[0])
                    {
                        // Chat Client
                        case 0x1:
                            // Verify OID by checking if it has any (none means full privileged cert) and matches the one on the whitelist
                            if (KeyUsages.Count > 0 &&
                                KeyUsages.Find((k)=>Array.IndexOf<string>(this.conf.ChatOID, k.Oid?.Value ?? "") != -1) == null)
                            {
                                await _rejectClient(unauthCli, unauthStream, "Certificate Unauthorized to access chat");
                                return;
                            }
                            await _acceptChatClient(unauthCli, unauthStream);
                            break;
                        // File Upload Client
                        case 0x2:
                            await _rejectClient(unauthCli, unauthStream, "Feature Unavailable");
                            break;
                        // File Receive Client
                        case 0x3:
                            await _rejectClient(unauthCli, unauthStream, "Feature Unavailable");
                            break;
                        // Bad Client Request
                        default:
                            await _rejectClient(unauthCli, unauthStream, "Invalid Client Request Detected");
                            return;
                    }

                }
                catch (AuthenticationException Aex)
                {
                    utils.print("A client's authentication occured an error", "AuthError");
                    unauthStream.Close();
                    unauthCli.Close();
                }
            }
        }




        // Handle all incoming message from TcpClients
        async private void _handlePlayerMessage(SslStream stream)
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
                utils.print(userMessage.ToString(), String.Format("{0} ({1})", stream.RemoteCertificate!.Subject, stream.RemoteCertificate.GetSerialNumberString()));
                await this.broadcastClient(Encoding.UTF8.GetBytes(String.Format("${0}\0${1}", stream.RemoteCertificate.Subject,userMessage.ToString())));
            }
        }




        // Handles client acceptance and welcome message
        async private Task _acceptChatClient(TcpClient cli, SslStream stream)
        {
            byte[] welcomeMsg = Encoding.UTF8.GetBytes(String.Format("Authentication Success: {0}", this.conf.MOTD));
            await stream.WriteAsync(welcomeMsg, 0, welcomeMsg.Length);
            ChatClient.Add(cli);
            ChatClientStream[cli] = stream;
            ChatClientThread[cli] = new Thread(() => _handlePlayerMessage(stream));
            ChatClientThread[cli].Start();
        }
        // Reject the client's connection after connection passes
        async private Task _rejectClient(TcpClient cli, SslStream stream, string reason = "")
        {
            byte[] msg = Encoding.UTF8.GetBytes(reason);
            await stream.WriteAsync(msg,0,msg.Length);
            await stream.ShutdownAsync();
            cli.Close();

        }



        /// <summary>
        /// Broadcast message to the clients
        /// </summary>
        /// <param name="message">The message to broadcast</param>
        /// <param name="client">(optional) The client which the message is broadcasted to, otherwise all client will be sent</param>
        async public Task broadcastClient(byte[] message, SslStream? stream=null)
        {
            if(stream != null)
            {
                await stream.WriteAsync(message,0,message.Length);
                return;
            }
            foreach(TcpClient cli in ChatClient)
                await ChatClientStream[cli].WriteAsync(message,0,message.Length);
        }
        async public Task gracefulShutdown()
        {
            // Close Chat client
            foreach(TcpClient cli in ChatClient)
            {
                ChatClientThread[cli].Interrupt();
                await ChatClientStream[cli].ShutdownAsync();
                ChatClientStream[cli].Dispose();
                cli.Close();

            }
        }
        async public Task closeClient()
        {

        }
    }
}
