using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using RoastInTheMiddle.Lib;

namespace RoastInTheMiddle.Command
{
    public class Roast
    {
        public static void Execute(Dictionary<string, string> arguments)
        {
            List<string> spns = null;
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
                spns = new List<string>();
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

            if (spns == null)
            {
                Console.WriteLine("[X] '/spns' argument is required to execute this application.");
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
                Console.WriteLine("[*] Starting RitM attack");
                RitM.Run(listenIP, targets, dcIPs, spns).Wait();
                Console.WriteLine("[*] Finished RitM attack");
            }
            else
            {
                Usage.Print();
            }
        }
    }
}
