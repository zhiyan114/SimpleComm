using Server;
using System.Security.Cryptography;
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

// Setup Network
NetworkManager? network = null;
do
{
    try
    {
        Console.WriteLine("Please enter server cert password (empty if none): ");
        string certPass = Console.ReadLine() ?? "";
        network = new NetworkManager(conf, certPass);
    } catch(CryptographicException)
    {
        utils.print("Invalid Certificate Password, try again");
    }
} while(network == null);

network.setupListenThread();
utils.print("Server is listening...");
while(true)
{
    string? message = Console.ReadLine();
    if(message != null && !string.IsNullOrWhiteSpace(message))
        await network.broadcastClient(Encoding.UTF8.GetBytes(String.Format("server\0{0}<EOF>", message.Replace("<EOF>", ""))));
}