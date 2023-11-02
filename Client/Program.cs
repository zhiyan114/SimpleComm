using Client;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

Console.Title = "SimpleComm Client Software (Not Connected)";
utils.print("SimpleComm Client Software Loaded...");

// Prompt for valid IP and Port
IPAddress? srvIP = null;
int srvPort = 0;
while(srvIP == null || srvPort == 0)
{
    Console.WriteLine("Enter server address to connect (IP or IP:PORT):");
    string? AddrInput = Console.ReadLine();
    if(AddrInput == null || string.IsNullOrWhiteSpace(AddrInput))
    {
        utils.print("No input detected", "ConnMgr");
        continue;
    }
    string[] AddrPort = AddrInput.Split(":");
    // Get the IP Address
    try
    {
        srvIP = IPAddress.Parse(AddrPort[0]);
    } catch(FormatException)
    {
        
        // Do a DNS parsing
        try
        {
            IPAddress[] addrs = Dns.GetHostAddresses(AddrPort[0]);
            if (addrs.Length == 0)
            {
                utils.print("No IP Address found", "ConnMgr");
                continue;
            }
            srvIP = addrs[0];
        } catch(SocketException)
        {
            utils.print("Invalid Domain Name or IP Address", "ConnMgr");
            continue;
        }
        
    }
    // Get the port number
    if (AddrPort.Length > 1)
    {
        try
        {
            srvPort = int.Parse(AddrPort[1]);
            if (srvPort <= 25565 && srvPort >= 1) break;
            utils.print("Invalid Port Number", "ConnMgr");
            srvPort = 0;
            continue;
        } catch(FormatException)
        {
            utils.print("Invalid Port Format Detected", "ConnMgr");
            continue;
        }
    } else
        srvPort = 19254;

}


// Prompt For Certificate
X509Certificate2? clientCert = null;
while(clientCert == null)
{
    Console.WriteLine("Enter Certificate Retrival Method (1=Windows Cert Store; 2=Smart Card; 3=PKCS#12 File):");
    try
    {
        string? AddrInput = Console.ReadLine();
        if (AddrInput == null)
        {
            utils.print("No input detected", "CertMgr");
            continue;
        }
        switch(int.Parse(AddrInput))
        {
            case 1:
                // Certificate Store
                if(!OperatingSystem.IsWindows())
                {
                    utils.print("Certificate Store is only supported on Windows", "CertMgr");
                    continue;
                }
                X509Store certStore = new X509Store("MY", StoreLocation.CurrentUser);
                certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection selectedCert = X509Certificate2UI.SelectFromCollection(certStore.Certificates, "Select Certificate", "Select one of the following certificate for client authentication", X509SelectionFlag.SingleSelection);
                if(selectedCert.Count == 0)
                {
                    utils.print("No Certificate Selected", "CertMgr");
                    continue;
                }
                clientCert = selectedCert[0];
                break;
            case 2:
                try
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        utils.print("Smart Card is only supported on Windows", "CertMgr");
                        continue;
                    }
                    // Pull single cert when not running as admin (due to API privilege)
                    if (!utils.isRunningAdmin())
                    {
                        utils.print("Smart Card Selection is only available when running as administrator");
                        clientCert = SmartCard.GetDefaultSmartCardCert();
                        if (clientCert != null) break;
                        utils.print("No smart card detected, try again");
                        continue;
                    }
                    // Pull all available cert when running as admin
                    X509Certificate2Collection selectedSmartCard = X509Certificate2UI.SelectFromCollection(SmartCard.GetCertificates(), "Select Smart Card", "Select one of the following smart card certificate for client authentication", X509SelectionFlag.SingleSelection);
                    if (selectedSmartCard.Count == 0)
                    {
                        utils.print("No Smart Card Selected", "CertMgr");
                        continue;
                    }
                    clientCert = selectedSmartCard[0];
                    break;
                } catch(CryptographicException)
                {
                    utils.print("No smart card detected, try again", "CertMgr");
                    continue;
                }
                
            case 3:
                // PKCS#12 File
                while (true)
                {
                    Console.WriteLine("Please enter the certificate path:");
                    string? CertPath = Console.ReadLine() ?? "";
                    if(!File.Exists(CertPath))
                    {
                        utils.print("Invalid Certificate Path", "CertMgr");
                        continue;
                    }
                    Console.WriteLine("Please enter the certificate password (or empty if none):");
                    string? CertPass = Console.ReadLine() ?? "";
                    try
                    {
                        clientCert = new X509Certificate2(CertPath, CertPass);
                        break;
                    }
                    catch (CryptographicException)
                    {
                        utils.print("Bad Certificate Password", "CertMgr");
                        continue;
                    }
                }
                break;
            default:
                utils.print("Invalid selection made", "CertMgr");
                break;
        }
    } catch (FormatException)
    {
        utils.print("Non-numerical input detected", "CertMgr");
        continue;
    }
}
utils.print(string.Format("Certificate: {0} ({1}) will now be used as authentication", utils.getCertCN(clientCert.SubjectName), clientCert.SerialNumber), "CertMgr");
NetworkManager network;
try
{
    network = new NetworkManager(srvIP, srvPort, clientCert);
} catch (SocketException)
{
    utils.print("Server is offline or the address you input was incorrect", null, true);
    return;
}
bool result = false;
try
{
    result = await network.initalHandshake();
} catch(AuthenticationException)
{
    utils.print("Invalid Certificate Credential Provided", null, true);
    return;
}
if (!result) { Console.ReadLine(); return;}
network.setupReceivingThread();
utils.print("Client Ready!");
while (true)
{
    string? message = Console.ReadLine();
    if (message != null && !string.IsNullOrWhiteSpace(message))
    {
        byte[] messageByte = Encoding.UTF8.GetBytes(String.Format("{0}<EOF>", message.Replace("<EOF>", "")));
        try
        {
            network.clientStream.Write(messageByte, 0, messageByte.Length);
        } catch(IOException)
        {
            break;
        }
    }
        
}