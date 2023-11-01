using Server;
using System.Net;
using System.Security.Cryptography.X509Certificates;

Console.Title = "SimpleComm Server Software";
utils.print("Loading up config files...");
ConfigManager confmgr = new ConfigManager("server.conf");
config? conf = confmgr.getConfig();

// Config checks
if(conf == null)
{
    if (confmgr.ConfigExists())
    {
        utils.print("Config file detected, but may have invalid format. If needed to, you can delete it and have the software generate a new config file", null, true);
        return 0;
    }
    confmgr.createEmptyConfig();
    utils.print("Config not detected, please refer to the config file and set it up before running the software again...");
    confmgr.printDoc();
    return 0;
}
utils.print("Config Loaded...");

// Assume checks are all passed, get the server cert password
Console.WriteLine("Please enter server cert password (empty if none): ");
string certPass = Console.ReadLine() ?? "";

// Get the server cert and pass it along

// Setup Network
NetworkManager network = new NetworkManager(conf, certPass);
utils.print("Server is listening...");
network.setupListenThread();
utils.print("Server is listening for client requests...");
while(true)
{
    Console.ReadLine();
}
return 0;