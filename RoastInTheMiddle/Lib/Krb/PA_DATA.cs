using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Asn1;

namespace RoastInTheMiddle.Lib.Krb
{
    public class PA_DATA
    {
        public PA_DATA(bool pac = true)
        {
            type = Interop.PADATA_TYPE.PA_PAC_REQUEST;

            value = new PA_PAC_REQUEST(pac);
        }

        /*public PA_DATA(string keyString, Interop.KERB_ETYPE etype)
        {
            type = Interop.PADATA_TYPE.ENC_TIMESTAMP;

            PA_ENC_TS_ENC temp = new PA_ENC_TS_ENC();

            byte[] rawBytes = temp.Encode().Encode();
            byte[] key = Helpers.StringToByteArray(keyString);

            // KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP == 1
            // From https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L55
            byte[] encBytes = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, key, rawBytes);

            value = new EncryptedData((int)etype, encBytes);
        }*/

        public PA_DATA(AsnElt body)
        {
            try
            {
                type = (Interop.PADATA_TYPE)body.Sub[0].Sub[0].GetInteger();
                byte[] valueBytes = body.Sub[1].Sub[0].GetOctetString();
            }
            catch
            {
                type = (Interop.PADATA_TYPE)body.Sub[0].Sub[0].Sub[0].GetInteger();
                byte[] valueBytes = body.Sub[0].Sub[1].Sub[0].GetOctetString();
            }

            switch (type)
            {
                case Interop.PADATA_TYPE.PA_PAC_REQUEST:
                    value = new PA_PAC_REQUEST(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
                    break;
                case Interop.PADATA_TYPE.ENC_TIMESTAMP:
                    value = new EncryptedData(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
                    break;
            }
        }

        public PA_DATA(string crealm, string cname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, bool opsec = false)
        {
            // include an AP-REQ, so PA-DATA for a TGS-REQ

            type = Interop.PADATA_TYPE.AP_REQ;

            // build the AP-REQ
            AP_REQ ap_req = new AP_REQ(crealm, cname, providedTicket, clientKey, etype);

            // make authenticator look more realistic
            if (opsec)
            {
                var rand = new Random();
                ap_req.authenticator.seq_number = (UInt32)rand.Next(1, Int32.MaxValue);
                // Could be useful to output the sequence number in case we implement KRB_PRIV or KRB_SAFE messages
                Console.WriteLine("[+] Sequence number is: {0}", ap_req.authenticator.seq_number);

                // randomize cusec to avoid fingerprinting
                ap_req.authenticator.cusec = rand.Next(0, 999999);
            }

            value = ap_req;
        }

        public AsnElt Encode()
        {
            // padata-type     [1] Int32
            AsnElt typeElt = AsnElt.MakeInteger((long)type);
            AsnElt nameTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { typeElt });
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, nameTypeSeq);

            AsnElt paDataElt;
            if (type == Interop.PADATA_TYPE.PA_PAC_REQUEST)
            {
                // used for AS-REQs

                // padata-value    [2] OCTET STRING -- might be encoded AP-REQ
                paDataElt = ((PA_PAC_REQUEST)value).Encode();
                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, paDataElt);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.ENC_TIMESTAMP)
            {
                // used for AS-REQs
                AsnElt blob = AsnElt.MakeBlob(((EncryptedData)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });
                blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, blobSeq });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.AP_REQ)
            {
                // used for TGS-REQs
                AsnElt blob = AsnElt.MakeBlob(((AP_REQ)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else
            {
                return null;
            }
        }

        public Interop.PADATA_TYPE type { get; set; }

        public Object value { get; set; }
    }
}
