using System;
using System.Collections.Generic;
using System.Text;
using Asn1;
using RoastInTheMiddle.Lib;

namespace RoastInTheMiddle.Lib.Krb
{
    public class KRB_ERROR
    {
        /* KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
             pvno            [0] INTEGER (5),
             msg-type        [1] INTEGER (30),
             ctime           [2] KerberosTime OPTIONAL,
             cusec           [3] Microseconds OPTIONAL,
             stime           [4] KerberosTime,
             susec           [5] Microseconds,
             error-code      [6] Int32,
             crealm          [7] Realm OPTIONAL,
             cname           [8] PrincipalName OPTIONAL,
             realm           [9] Realm -- service realm --,
             sname           [10] PrincipalName -- service name --,
             e-text          [11] KerberosString OPTIONAL,
             e-data          [12] OCTET STRING OPTIONAL
           }*/

        public KRB_ERROR(byte[] errorBytes)
        {

        }

        public KRB_ERROR(PrincipalName serverName, string domain, Interop.KERBEROS_ERROR err)
        {
            var rand = new Random();
            pvno = 5;
            msg_type = (long)Interop.KERB_MESSAGE_TYPE.ERROR;
            stime = DateTime.UtcNow;
            susec = rand.Next(0, 999999);
            error_code = (long)err;
            realm = domain;
            sname = serverName;
        }

        public KRB_ERROR(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        msg_type = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        ctime = s.Sub[0].GetTime();
                        break;
                    case 3:
                        cusec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 4:
                        stime = s.Sub[0].GetTime();
                        break;
                    case 5:
                        susec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 6:
                        error_code = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 7:
                        crealm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 8:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 9:
                        realm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 10:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 11:
                        e_text = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 12:
                        try
                        {
                            e_data = new List<PA_DATA>();
                            AsnElt tmpData = AsnElt.Decode(s.Sub[0].GetOctetString());
                            foreach (AsnElt tmp in tmpData.Sub)
                            {
                                e_data.Add(new PA_DATA(tmp));
                            }
                        }
                        catch (NullReferenceException)
                        {
                            e_data = null;
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // pvno            [0] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);
            allNodes.Add(pvnoSeq);


            // msg-type        [1] INTEGER (30)
            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_type_ASNSeq);
            allNodes.Add(msg_type_ASNSeq);

            // stime[4] KerberosTime
            AsnElt stimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, ctime.ToString("yyyyMMddHHmmssZ"));
            AsnElt stimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { stimeAsn });
            stimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, stimeSeq);
            allNodes.Add(stimeSeq);

            // susec[5] Microseconds
            AsnElt susecAsn = AsnElt.MakeInteger(susec);
            AsnElt susecSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { susecAsn });
            susecSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, susecSeq);
            allNodes.Add(susecSeq);

            // error - code[6] Int32
            AsnElt errAsn = AsnElt.MakeInteger(error_code);
            AsnElt errSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { errAsn });
            errSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, errSeq);
            allNodes.Add(errSeq);

            // realm           [9] Realm -- service realm --
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, realmSeq);
            allNodes.Add(realmSeq);

            // sname[10] PrincipalName-- service name --
            AsnElt snameElt = sname.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 10, snameElt);
            allNodes.Add(snameElt);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());

            // KRB-ERROR       ::= [APPLICATION 30] SEQUENCE
            //  put it all together and tag it with 30
            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 30, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public DateTime ctime { get; set; }

        public long cusec { get; set; }

        public DateTime stime { get; set; }

        public long susec { get; set; }

        public long error_code { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public string e_text { get; set; }

        public List<PA_DATA> e_data { get; set; }
    }
}
