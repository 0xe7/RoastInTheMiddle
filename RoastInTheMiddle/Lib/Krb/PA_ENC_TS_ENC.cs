using System;
using Asn1;

namespace RoastInTheMiddle.Lib.Krb
{
    public class PA_ENC_TS_ENC
    {
        public PA_ENC_TS_ENC()
        {
            patimestamp = DateTime.UtcNow;
            timestampData = null;
        }

        public PA_ENC_TS_ENC(DateTime time)
        {
            patimestamp = time;
            timestampData = null;
        }

        public PA_ENC_TS_ENC(AsnElt value)
        {
            timestampData = value.CopyValue();
        }

        public AsnElt Encode()
        {
            AsnElt totalSeq;
            if (timestampData == null)
            {
                AsnElt patimestampAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, patimestamp.ToString("yyyyMMddHHmmssZ"));
                AsnElt patimestampSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampAsn });
                patimestampSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, patimestampSeq);

                totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampSeq });
            }
            else
            {
                totalSeq = AsnElt.Decode(timestampData);
            }
            

            return totalSeq;
        }

        public byte[] timestampData { get; set; }

        public DateTime patimestamp { get; set; }

        public int pausec { get; set; }
    }
}
