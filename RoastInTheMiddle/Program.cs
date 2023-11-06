using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using RoastInTheMiddle.Command;
using RoastInTheMiddle.Lib.Krb;

namespace RoastInTheMiddle
{
    class Program
    {
        public static bool isRunning = true;
        public static bool wrap = false;
        public static bool verbose = false;
        public static string command = string.Empty;
        public static KRB_CRED tgt = null;

        public static ConcurrentDictionary<string, Object> shared = new ConcurrentDictionary<string, Object>();
        public static ConcurrentQueue<AS_REQ> asReqs = new ConcurrentQueue<AS_REQ>();

        static void Main(string[] args)
        {
            /*Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) {
                e.Cancel = true;
                Program.isRunning = false;
            };*/
            command = args[0].ToLower();

            var parsed = ArgumentParser.Parse(args.Skip(1));
            if (parsed.ParsedOk == false)
            {
                Console.WriteLine("[X] Incorrect arguments passed, please check and try again.\r\n");
                return;
            }

            if (parsed.Arguments.ContainsKey("/wrap"))
            {
                wrap = true;
            }

            if (command.Equals("kerberoast") || command.Equals("sessionroast"))
            {
                Roast.Execute(parsed.Arguments);
            }
            else
            {
                Console.WriteLine($"[X] Incorrect command passed ({command}), please check and try again.\r\n");
                return;
            }
        }
    }
}
