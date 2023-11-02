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
            foreach (string SubjectName in name.Name.Split(", "))
            {
                string[] names = SubjectName.Split("=");
                if (names[0] == "CN") return names[1];
            }
            return "CN NULL";
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
