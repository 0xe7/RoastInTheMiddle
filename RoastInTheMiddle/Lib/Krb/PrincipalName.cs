using System.Collections.Generic;
using System.Text;
using Asn1;

namespace RoastInTheMiddle.Lib.Krb
{
    public class PrincipalName
    {
        public PrincipalName()
        {
            name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;

            name_string = new List<string>();
        }

        public PrincipalName(string principal)
        {
            // create with principal
            name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;

            name_string = new List<string>();
            name_string.Add(principal);
        }

        public PrincipalName(AsnElt body)
        {
            name_type = (Interop.PRINCIPAL_TYPE)body.Sub[0].Sub[0].GetInteger();

            int numberOfNames = body.Sub[1].Sub[0].Sub.Length;

            name_string = new List<string>();

            for (int i = 0; i < numberOfNames; i++)
            {
                name_string.Add(Encoding.UTF8.GetString(body.Sub[1].Sub[0].Sub[i].GetOctetString()));
            }
        }

        public AsnElt Encode()
        {
            // name-type[0] Int32
            AsnElt nameTypeElt = AsnElt.MakeInteger((long)name_type);
            AsnElt nameTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeElt });
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, nameTypeSeq);


            // name-string[1] SEQUENCE OF KerberosString
            //  add in the name string sequence (one or more)
            AsnElt[] strings = new AsnElt[name_string.Count];

            for (int i = 0; i < name_string.Count; ++i)
            {
                string name = name_string[i];
                AsnElt nameStringElt = AsnElt.MakeString(AsnElt.UTF8String, name);
                nameStringElt = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, nameStringElt);
                strings[i] = nameStringElt;
            }

            AsnElt stringSeq = AsnElt.Make(AsnElt.SEQUENCE, strings);
            AsnElt stringSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { stringSeq });
            stringSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, stringSeq2);


            // build the final sequences
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nameTypeSeq, stringSeq2 });

            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });

            return seq2;
        }

        public Interop.PRINCIPAL_TYPE name_type { get; set; }

        public List<string> name_string { get; set; }
    }
}
