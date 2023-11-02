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
                SslStream unauthStream = new SslStream(unauthCli.GetStream(), false,(a,b,c,d)=>true);
                try
                {
                    await unauthStream.AuthenticateAsServerAsync(this.serverCert, true, false);

                    if (unauthStream.RemoteCertificate == null) { await _rejectChatClient(unauthCli, unauthStream, "Certificate is required to authenticate you"); continue; }
                    X509Certificate2 cliCert = new X509Certificate2(unauthStream.RemoteCertificate);


                    /* START CERTIFICATE VALIDATION CODES START */

                    // Expiration Validation
                    try
                    {
                        DateTime expire = DateTime.Parse(cliCert.GetExpirationDateString());
                        if(expire.Subtract(DateTime.Now).Ticks < 0)
                        {
                            await _rejectChatClient(unauthCli, unauthStream, "The certificate you presented was expired");
                            continue;
                        }
                    } catch(FormatException)
                    {
                        // Undefined Expiration Date (perhaps, using XCA no well-defined expiration)
                        await _rejectChatClient(unauthCli, unauthStream, "A valid expiration date must be presented on the certificate");
                        continue;
                    }

                    // CA Verify
                    X509Chain certChain = new X509Chain();
                    certChain.Build(cliCert);
                    bool isCASponsored = false;
                    
                    // Reject self-signed cert
                    if(certChain.ChainElements.Count < 2) { await _rejectChatClient(unauthCli, unauthStream, "Self-signed certificates are not allowed"); continue; }

                    // Validate Chain (and not self)
                    foreach (X509ChainElement cert in certChain.ChainElements)
                        if(cert.Certificate.Thumbprint != cliCert.Thumbprint)
                            isCASponsored = Array.Find<string>(this.conf.CAFingerprint, (a)=>a.ToLower() == cert.Certificate.Thumbprint.ToLower()) != null;
                    if(!isCASponsored) { await _rejectChatClient(unauthCli, unauthStream, "Certificate is not issued by an authorized CA"); continue; }

                    // Check if the client has been blacklisted
                    if (Array.Find<string>(this.conf.BannedSerial, (k) => k.ToLower().Equals(cliCert.SerialNumber.ToLower())) != null)
                    {
                        await _rejectChatClient(unauthCli, unauthStream, "Certificate Serial Blacklisted");
                        continue;
                    }

                    /* END CERTIFICATE VALIDATION CODES END */


                    // Get client type request
                    byte[] req = new byte[1];
                    await unauthStream.ReadAsync(req, 0, req.Length);

                    List<X509EnhancedKeyUsageExtension> KeyUsages = cliCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
                    switch (req[0])
                    {
                        // Chat Client
                        case 0x1:
                            // Verify OID by checking if it has any (none means full privileged cert) and matches the one on the whitelist
                            if (conf.ChatOID.Length > 0 &&
                                KeyUsages.Count > 0 &&
                                KeyUsages.Find((k)=>Array.IndexOf<string>(this.conf.ChatOID, k.Oid?.Value ?? "") != -1) == null)
                            {
                                await _rejectChatClient(unauthCli, unauthStream, "Certificate Unauthorized to access chat");
                                return;
                            }
                            await _acceptChatClient(unauthCli, unauthStream);
                            break;
                        // File Upload Client
                        case 0x2:
                            await _rejectChatClient(unauthCli, unauthStream, "Feature Unavailable");
                            break;
                        // File Receive Client
                        case 0x3:
                            await _rejectChatClient(unauthCli, unauthStream, "Feature Unavailable");
                            break;
                        // Bad Client Request
                        default:
                            await _rejectChatClient(unauthCli, unauthStream, "Invalid Client Request Detected");
                            return;
                    }

                }
                catch (AuthenticationException)
                {
                    utils.print("A client's authentication occured an error", "AuthError");
                    unauthStream.Close();
                    unauthCli.Close();
                }
                catch(IOException)
                {
                    utils.print("An unknown client attempted authentication, but disconnected...", "AuthError");
                }
            }
        }




        // Handle all incoming message from TcpClients
        async private void _handlePlayerMessage(TcpClient cli)
        {
            SslStream stream = ChatClientStream[cli];
            bool clientClosed = false;
            while (!clientClosed)
            {
                // Read all the available messages
                int LeftByte = -1;
                StringBuilder userMessage = new StringBuilder();
                do
                {
                    byte[] msgBuffer = new byte[1024];
                    try
                    {
                        LeftByte = await stream.ReadAsync(msgBuffer, 0, msgBuffer.Length);
                    } catch(IOException)
                    {
                        // Client Closed
                        await closeClient(cli);
                        clientClosed = true;
                        break;
                    }
                    userMessage.Append(Encoding.UTF8.GetString(msgBuffer));
                    if (userMessage.ToString().IndexOf("<EOF>") != -1) break;
                } while (LeftByte != 0);
                if (clientClosed) break;
                string[] Messages = userMessage.ToString().Split("<EOF>");
                // Get all the seperate message and process them, ignore the last item since I'll be empty
                for(int i = 0; i < Messages.Length-1; i++)
                {
                    X509Certificate2 remoteCert = new X509Certificate2(stream.RemoteCertificate!);
                    utils.print(Messages[i].ToString(), String.Format("{0} ({1})", utils.getCertCN(remoteCert.SubjectName), remoteCert.GetSerialNumberString()));
                    await this.broadcastExcludeClient(Encoding.UTF8.GetBytes(String.Format("{0}\0{1}<EOF>", utils.getCertCN(remoteCert.SubjectName), Messages[i].ToString())), cli);
                }
            }
        }




        // Handles client acceptance and welcome message
        async private Task _acceptChatClient(TcpClient cli, SslStream stream)
        {
            byte[] welcomeMsg = Encoding.UTF8.GetBytes(String.Format("0:{0}", this.conf.MOTD));
            await stream.WriteAsync(welcomeMsg, 0, welcomeMsg.Length);
            ChatClient.Add(cli);
            ChatClientStream[cli] = stream;
            ChatClientThread[cli] = new Thread(() => _handlePlayerMessage(cli));
            ChatClientThread[cli].Start();
            X509Certificate2 cliCert = new X509Certificate2(stream.RemoteCertificate!);
            utils.print("Accepted Chat Client", string.Format("{0} ({1})", utils.getCertCN(cliCert.SubjectName), cliCert.SerialNumber));
        }
        // Reject the client's connection after connection passes
        async private Task _rejectChatClient(TcpClient cli, SslStream stream, string reason = "")
        {
            byte[] msg = Encoding.UTF8.GetBytes("1:"+reason);
            await stream.WriteAsync(msg,0,msg.Length);
            X509Certificate2 cliCert = new X509Certificate2(stream.RemoteCertificate!);
            utils.print("Rejected Chat Client: "+reason, string.Format("{0} ({1})", utils.getCertCN(cliCert.SubjectName), cliCert.SerialNumber));
            // Cleanup connection in 15s to ensure client gets the message and self-disconnect...
            Timer? timeoutDel = null;
            timeoutDel = new Timer((state) =>
            {
                // stream.ShutdownAsync();
                stream.Close();
                cli.Close();
                timeoutDel?.Dispose();
            }, null,15000, Timeout.Infinite);

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
                await ChatClientStream[cli].WriteAsync(message, 0, message.Length);
        }
        async public Task broadcastExcludeClient(byte[] message, params TcpClient[] ignoreClient)
        {
            foreach (TcpClient cli in ChatClient)
                if(!ignoreClient.Contains(cli))
                    await ChatClientStream[cli].WriteAsync(message, 0, message.Length);
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
        async public Task closeClient(TcpClient cli, bool graceful=false)
        {
            if(graceful)
            {
                await ChatClientStream[cli].ShutdownAsync();
            }
            X509Certificate2 userID = new X509Certificate2(ChatClientStream[cli].RemoteCertificate!);
            utils.print("Client Disconnected", String.Format("{0} ({1})", utils.getCertCN(userID.SubjectName), userID.SerialNumber));
            cli.Close();
            ChatClientStream[cli].Close();
            ChatClientThread[cli].Interrupt();
            ChatClientThread.Remove(cli);
            ChatClientStream.Remove(cli);
            ChatClient.Remove(cli);
        }
    }
}
