using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class ConfigManager
    {
        // Function that loads up the config
        string fileName = string.Empty;
        public ConfigManager(string ConfigName)
        { 
            this.fileName = ConfigName;
        }
        public bool ConfigExists()
        {
            return File.Exists(fileName);
        }
        // Pull the config from the file, otherwise null if not found
        public config? getConfig()
        {
            if (!File.Exists(this.fileName)) return null;
            try
            {
                return JsonConvert.DeserializeObject<config>(File.ReadAllText(this.fileName));
            } catch(Exception ex) {
                utils.print("Exception Detected:" + ex, "Error Manager");
                return null;
            }
        }
        // Create an empty config file based on config class properties
        public void createEmptyConfig()
        {
            File.WriteAllText(this.fileName, JsonConvert.SerializeObject(new config(), Formatting.Indented));
        }
        // Worse way to print a documentation for a config file..
        public void printDoc()
        {
            utils.print(@"
For documentation purpose, here is what each config is for
* ChatOID - List of OID that allows the user to chat (typically set in the ExtendedKeyUsage of a cert)
* UploadOID - Same as ChatOID, but for file upload privilege
* CAFingerprint - List of CA fingerprint that'll be accepted
* BannedSerial - Banned Cert serials, software may or may not involve CRL/OCSP checks so be wary
* serverCertName - PKCS12 file for the server cert (.pfx, .p12, etc.)
* IP - IP that'll be listening to (default: 0.0.0.0)
* Port - software port (default: 19254)
                ", null, true);
        }
    }
    // Config Objects
    public class config
    {
        public string[] ChatOID;
        public string[] UploadOID;
        public string[] CAFingerprint;
        public string[] BannedSerial;
        public string serverCertName;
        public string MOTD;
        public string IP;
        public int Port;
        [JsonConstructor]
        internal config(string[]? ChatOID = null,
            string[]? UploadOID = null,
            string[]? CAFingerprint = null,
            string[]? BannedSerial = null,
            string? serverCertName = null,
            string? MOTD = null,
            string? IP = null,
            int? Port = null)
        {
            this.ChatOID = ChatOID ?? Array.Empty<string>();
            this.UploadOID = UploadOID ?? Array.Empty<string>();
            this.CAFingerprint = CAFingerprint ?? Array.Empty<string>();
            this.BannedSerial = BannedSerial ?? Array.Empty<string>();
            this.serverCertName = serverCertName ?? string.Empty;
            this.MOTD = MOTD ?? "Welcome to SimpleComm Server UwU";
            this.IP = IP ?? "0.0.0.0";
            this.Port = Port ?? 19254;
        }

    }
}
