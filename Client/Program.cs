﻿using Client;
using System.Net;
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
    if(AddrInput == null)
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
        IPAddress[] addrs = Dns.GetHostAddresses(AddrPort[0]);
        if(addrs.Length == 0)
        {
            utils.print("Invalid IP Address", "ConnMgr");
            continue;
        }
        srvIP = addrs[0];
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
    Console.WriteLine("Enter Certificate Retrival Method (1=Windows Cert Store; 2=Smart Card; 3=PKCS#12 File): ");
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
                // Smart Card Store
                utils.print("Please use the certificate store to find your smart card for now", "CertMgr");
                continue;
                if (!OperatingSystem.IsWindows())
                {
                    utils.print("Smart Card is only supported on Windows", "CertMgr");
                    continue;
                }
                X509Certificate2Collection selectedSmartCard = X509Certificate2UI.SelectFromCollection(SmartCard.GetCertificates(), "Select Smart Card", "Select one of the following smart card certificate for client authentication", X509SelectionFlag.SingleSelection);
                if (selectedSmartCard.Count == 0)
                {
                    utils.print("No Smart Card Selected", "CertMgr");
                    continue;
                }
                break;
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
NetworkManager network = new NetworkManager(srvIP, srvPort, clientCert);
bool result = await network.initalHandshake();
if (!result) return;
network.setupReceivingThread();
utils.print("Connection Complete!");
while (true)
{
    string? message = Console.ReadLine();
    byte[] messageByte = Encoding.UTF8.GetBytes(String.Format("{0}<EOF>", message.Replace("<EOF>", "")));
    if (message != null)
        network.clientStream.Write(messageByte,0, messageByte.Length);
}