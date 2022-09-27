using Asn1;

namespace RoastInTheMiddle.Lib.Krb
{
    public class PA_PAC_REQUEST
    {
        public PA_PAC_REQUEST(bool pac = true)
        {
            include_pac = pac;
        }

        public PA_PAC_REQUEST(AsnElt value)
        {
            include_pac = value.Sub[0].Sub[0].GetBoolean();
        }

        public AsnElt Encode()
        {
            AsnElt ret;

            if (include_pac)
            {
                ret = AsnElt.MakeBlob(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 });
            }
            else
            {
                ret = AsnElt.MakeBlob(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00 });
            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { ret });

            return seq;
        }

        public bool include_pac { get; set; }
    }
}
