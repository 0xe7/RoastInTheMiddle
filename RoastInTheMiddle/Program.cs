using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using RoastInTheMiddle.Command;
using RoastInTheMiddle.Lib.Krb;

namespace RoastInTheMiddle
{
    class Program
    {
        public static bool isRunning = true;
        public static bool wrap = false;
        public static bool verbose = false;

        public static ConcurrentDictionary<string, Object> shared = new ConcurrentDictionary<string, Object>();
        public static ConcurrentQueue<AS_REQ> asReqs = new ConcurrentQueue<AS_REQ>();

        static void Main(string[] args)
        {
            /*Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) {
                e.Cancel = true;
                Program.isRunning = false;
            };*/

            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Console.WriteLine("[X] Incorrect arguments passed, please check and try again.\r\n");
                return;
            }

            if (parsed.Arguments.ContainsKey("/wrap"))
            {
                wrap = true;
            }

            Roast.Execute(parsed.Arguments);
        }
    }
}
