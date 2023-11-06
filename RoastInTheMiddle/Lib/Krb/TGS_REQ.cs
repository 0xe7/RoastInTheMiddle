using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Asn1;

namespace RoastInTheMiddle.Lib.Krb
{
    public class TGS_REQ
    {
        public static byte[] NewTGSReq(string userName, string domain, string sname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Ticket ticket)
        {
            TGS_REQ req = new TGS_REQ();

            // the realm (domain) the user exists in
            req.req_body.realm = domain.ToUpper();

            req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_md5);
            
            req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.ENCTKTINSKEY | Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;
            req.req_body.sname.name_string.Add(sname);
            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;

            req.req_body.additional_tickets = new List<Ticket>();
            req.req_body.additional_tickets.Add(ticket);

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, paEType, false);
            req.padata.Add(padata);

            return req.Encode().Encode();
        }

        public TGS_REQ()
        {
            // default, for creation
            pvno = 5;

            // msg-type        [2] INTEGER (12 -- TGS)
            msg_type = (long)Interop.KERB_MESSAGE_TYPE.TGS_REQ;

            padata = new List<PA_DATA>();

            req_body = new KDCReqBody(c: false);
        }

        public AsnElt Encode()
        {
            // pvno            [1] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, pvnoSeq);


            // msg-type        [2] INTEGER (12 -- TGS -- )
            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, msg_type_ASNSeq);


            // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata)
            {
                padatas.Add(pa.Encode());
            }
            AsnElt padata_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, padatas.ToArray());
            AsnElt padata_ASNSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { padata_ASNSeq });
            padata_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, padata_ASNSeq2);


            // req-body        [4] KDC-REQ-BODY
            AsnElt req_Body_ASN = req_body.Encode();
            AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
            req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);


            // encode it all into a sequence
            AsnElt[] total = new[] { pvnoSeq, msg_type_ASNSeq, padata_ASNSeq, req_Body_ASNSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            // TGS-REQ         ::= [APPLICATION 12] KDC-REQ
            //  put it all together and tag it with 10
            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 12, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }
    }
}
