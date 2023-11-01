using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public static class utils
    {
        public static void print(string message, string? user=null, bool pause=false)
        {
            string msg = string.Format("[{0}] ({1}): {2}", user ?? "SimpleComm", DateTime.Now.ToString("t"), message);
            Console.WriteLine(msg);
            if (pause) Console.ReadLine();
        }
        public static string getCertCN(X500DistinguishedName name)
        {
            return name.Name.Split(", ")[0].Split("=")[1];
        }
        public static bool clientIsConnected(Socket socket)
        {
            try
            {
                return !(socket.Poll(1, SelectMode.SelectRead) && socket.Available == 0);
            }
            catch (SocketException) { return false; }
        }
    }
}
