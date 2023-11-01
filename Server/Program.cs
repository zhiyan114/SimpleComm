using Server;
using System.Text;

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

// Setup Network
NetworkManager network = new NetworkManager(conf, certPass);
network.setupListenThread();
utils.print("Server is listening...");
while(true)
{
    string? message = Console.ReadLine();
    if(message != null)
        await network.broadcastClient(Encoding.UTF8.GetBytes(String.Format("server\0{0}<EOF>", message.Replace("<EOF>", ""))));
}