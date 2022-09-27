using Asn1;
using System;
using System.Collections.Generic;

namespace RoastInTheMiddle.Lib.Krb
{
    public class AS_REQ
    {
        public AS_REQ(byte[] data)
        {
            // decode the supplied bytes to an AsnElt object
            data = AsnIO.FindBER(data);
            AsnElt asn_AS_REQ = AsnElt.Decode(data);
            padata = new List<PA_DATA>();

            // AS-REQ::= [APPLICATION 10] KDC-REQ
            //  tag class == 1
            //  tag class == 10
            //  SEQUENCE
            if (asn_AS_REQ.TagValue != (int)Interop.KERB_MESSAGE_TYPE.AS_REQ)
            {
                throw new System.Exception("AS-REQ tag value should be 10");
            }

            if ((asn_AS_REQ.Sub.Length != 1) || (asn_AS_REQ.Sub[0].TagValue != 16))
            {
                throw new System.Exception("First AS-REQ sub should be a sequence");
            }

            // extract the KDC-REQ out
            AsnElt[] kdc_req = asn_AS_REQ.Sub[0].Sub;

            foreach (AsnElt s in kdc_req)
            {
                switch (s.TagValue)
                {
                    case 1:
                        pvno = s.Sub[0].GetInteger();
                        break;
                    case 2:
                        msg_type = s.Sub[0].GetInteger();
                        break;
                    case 3:
                        foreach (AsnElt pa in s.Sub[0].Sub)
                        {
                            padata.Add(new PA_DATA(pa));
                        }
                        break;
                    case 4:
                        req_body = new KDCReqBody(s.Sub[0]);
                        break;
                    default:
                        throw new System.Exception(String.Format("Invalid tag AS-REQ value : {0}", s.TagValue));
                }
            }
        }

        public AsnElt Encode()
        {
            // pvno            [1] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, pvnoSeq);


            // msg-type        [2] INTEGER (10 -- AS -- )
            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, msg_type_ASNSeq);

            // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata)
            {
                padatas.Add(pa.Encode());
            }

            // req-body        [4] KDC-REQ-BODY
            AsnElt req_Body_ASN = req_body.Encode();
            AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
            req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);

            AsnElt padata_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, padatas.ToArray());
            AsnElt padata_ASNSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { padata_ASNSeq });
            padata_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, padata_ASNSeq2);

            // encode it all into a sequence
            AsnElt[] total = new[] { pvnoSeq, msg_type_ASNSeq, padata_ASNSeq, req_Body_ASNSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            // AS-REQ          ::= [APPLICATION 10] KDC-REQ
            //  put it all together and tag it with 10
            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 10, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }
    }
}
