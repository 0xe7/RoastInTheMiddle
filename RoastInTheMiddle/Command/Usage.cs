using System;
using System.IO;

namespace RoastInTheMiddle.Command
{
    class Usage
    {
        public static void Print()
        {
            string[] cmd = Environment.GetCommandLineArgs()[0].Split(Path.DirectorySeparatorChar);
            Console.WriteLine($"Usage: {cmd[cmd.Length - 1]} /listenip:[IP ADDRESS] /spns:[SPNS]");
        }
    }
}
