using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public static class utils
    {
        public static void print(string message, string? user=null, bool pause=false)
        {
            string msg = string.Format("[{0}] ({1}): {2}", user ?? "SimpleComm", DateTime.Now.ToString("t"), message);
            Console.WriteLine(msg);
            if (pause) Console.ReadLine();
        }
    }
}
