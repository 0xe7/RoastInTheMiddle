using System;
using System.IO;

namespace RoastInTheMiddle.Command
{
    class Usage
    {
        public static void Print()
        {
            string[] cmd = Environment.GetCommandLineArgs()[0].Split(Path.DirectorySeparatorChar);
            Console.WriteLine("Kerberoast command:\n");
            Console.WriteLine($"Usage: {cmd[cmd.Length - 1]} kerberoast /listenip:[IP ADDRESS] /dcs:[IP1,IP2...] /targets:[IP1,IP2...] /spns:[SPNS]");
            Console.WriteLine("\nSessionroast command:\n");
            Console.WriteLine($"Usage: {cmd[cmd.Length - 1]} sessionroast /listenip:[IP ADDRESS] /dcs:[IP1,IP2...] /targets:[IP1,IP2...] /tgt:[B64|FILE KIRBI]");
        }
    }
}
