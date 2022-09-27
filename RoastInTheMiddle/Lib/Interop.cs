using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RoastInTheMiddle.Lib
{
    public class Interop
    {
        public const int KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1;

        public enum KERB_MESSAGE_TYPE : long
        {
            AS_REQ = 10,
            AS_REP = 11,
            CRED = 22,
            ERROR = 30
        }

        public enum KERB_ETYPE : Int32
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65,
            old_exp = -135
        }

        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENCTKTINSKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CONSTRAINED_DELEGATION = 0x00020000,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00004000,
            OK_AS_DELEGATE = 0x00040000,
            REQUEST_ANONYMOUS = 0x00008000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        public enum PRINCIPAL_TYPE : long
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10
        }

        public enum PADATA_TYPE : UInt32
        {
            ENC_TIMESTAMP = 2,
            PA_PAC_REQUEST = 128
        }

        public enum HostAddressType : long
        {
            NULL = 0,
            ADDRTYPE_UNIX = 1,
            ADDRTYPE_INET = 2,
            ADDRTYPE_IMPLINK = 3,
            ADDRTYPE_PUP = 4,
            ADDRTYPE_CHAOS = 5,
            ADDRTYPE_XNS = 6,
            ADDRTYPE_IPX = 6,
            ADDRTYPE_OSI = 7,
            ADDRTYPE_ECMA = 8,
            ADDRTYPE_DATAKIT = 9,
            ADDRTYPE_CCITT = 10,
            ADDRTYPE_SNA = 11,
            ADDRTYPE_DECNET = 12,
            ADDRTYPE_DLI = 13,
            ADDRTYPE_LAT = 14,
            ADDRTYPE_HYLINK = 15,
            ADDRTYPE_APPLETALK = 16,
            ADDRTYPE_VOICEVIEW = 18,
            ADDRTYPE_FIREFOX = 19,
            ADDRTYPE_NETBIOS = 20,
            ADDRTYPE_BAN = 21,
            ADDRTYPE_ATM = 22,
            ADDRTYPE_INET6 = 24
        }

        public enum KERBEROS_ERROR : UInt32
        {
            KDC_ERR_NONE = 0x0, //No error
            KDC_ERR_NAME_EXP = 0x1, //Client's entry in KDC database has expired
            KDC_ERR_SERVICE_EXP = 0x2, //Server's entry in KDC database has expired
            KDC_ERR_BAD_PVNO = 0x3, //Requested Kerberos version number not supported
            KDC_ERR_C_OLD_MAST_KVNO = 0x4, //Client's key encrypted in old master key
            KDC_ERR_S_OLD_MAST_KVNO = 0x5, //Server's key encrypted in old master key
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6, //Client not found in Kerberos database
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7, //Server not found in Kerberos database
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8, //Multiple principal entries in KDC database
            KDC_ERR_NULL_KEY = 0x9, //The client or server has a null key (master key)
            KDC_ERR_CANNOT_POSTDATE = 0xA, // Ticket (TGT) not eligible for postdating
            KDC_ERR_NEVER_VALID = 0xB, // Requested start time is later than end time
            KDC_ERR_POLICY = 0xC, //Requested start time is later than end time
            KDC_ERR_BADOPTION = 0xD, //KDC cannot accommodate requested option
            KDC_ERR_ETYPE_NOTSUPP = 0xE, // KDC has no support for encryption type
            KDC_ERR_SUMTYPE_NOSUPP = 0xF, // KDC has no support for checksum type
            KDC_ERR_PADATA_TYPE_NOSUPP = 0x10, //KDC has no support for PADATA type (pre-authentication data)
            KDC_ERR_TRTYPE_NO_SUPP = 0x11, //KDC has no support for transited type
            KDC_ERR_CLIENT_REVOKED = 0x12, // Client’s credentials have been revoked
            KDC_ERR_SERVICE_REVOKED = 0x13, //Credentials for server have been revoked
            KDC_ERR_TGT_REVOKED = 0x14, //TGT has been revoked
            KDC_ERR_CLIENT_NOTYET = 0x15, // Client not yet valid—try again later
            KDC_ERR_SERVICE_NOTYET = 0x16, //Server not yet valid—try again later
            KDC_ERR_KEY_EXPIRED = 0x17, // Password has expired—change password to reset
            KDC_ERR_PREAUTH_FAILED = 0x18, //Pre-authentication information was invalid
            KDC_ERR_PREAUTH_REQUIRED = 0x19, // Additional preauthentication required
            KDC_ERR_SERVER_NOMATCH = 0x1A, //KDC does not know about the requested server
            KDC_ERR_MUST_USE_USER2USER = 0x1B,
            KDC_ERR_PATH_NOT_ACCEPTED = 0x1C,
            KDC_ERR_SVC_UNAVAILABLE = 0x1D, // KDC is unavailable (modified as stated here: https://github.com/dotnet/Kerberos.NET/blob/develop/Kerberos.NET/Entities/Krb/KerberosErrorCode.cs)
            KRB_AP_ERR_BAD_INTEGRITY = 0x1F, // Integrity check on decrypted field failed
            KRB_AP_ERR_TKT_EXPIRED = 0x20, // The ticket has expired
            KRB_AP_ERR_TKT_NYV = 0x21, //The ticket is not yet valid
            KRB_AP_ERR_REPEAT = 0x22, // The request is a replay
            KRB_AP_ERR_NOT_US = 0x23, //The ticket is not for us
            KRB_AP_ERR_BADMATCH = 0x24, //The ticket and authenticator do not match
            KRB_AP_ERR_SKEW = 0x25, // The clock skew is too great
            KRB_AP_ERR_BADADDR = 0x26, // Network address in network layer header doesn't match address inside ticket
            KRB_AP_ERR_BADVERSION = 0x27, // Protocol version numbers don't match (PVNO)
            KRB_AP_ERR_MSG_TYPE = 0x28, // Message type is unsupported
            KRB_AP_ERR_MODIFIED = 0x29, // Message stream modified and checksum didn't match
            KRB_AP_ERR_BADORDER = 0x2A, // Message out of order (possible tampering)
            KRB_AP_ERR_BADKEYVER = 0x2C, // Specified version of key is not available
            KRB_AP_ERR_NOKEY = 0x2D, // Service key not available
            KRB_AP_ERR_MUT_FAIL = 0x2E, // Mutual authentication failed
            KRB_AP_ERR_BADDIRECTION = 0x2F, // Incorrect message direction
            KRB_AP_ERR_METHOD = 0x30, // Alternative authentication method required
            KRB_AP_ERR_BADSEQ = 0x31, // Incorrect sequence number in message
            KRB_AP_ERR_INAPP_CKSUM = 0x32, // Inappropriate type of checksum in message (checksum may be unsupported)
            KRB_AP_PATH_NOT_ACCEPTED = 0x33, // Desired path is unreachable
            KRB_ERR_RESPONSE_TOO_BIG = 0x34, // Too much data
            KRB_ERR_GENERIC = 0x3C, // Generic error; the description is in the e-data field
            KRB_ERR_FIELD_TOOLONG = 0x3D, // Field is too long for this implementation
            KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E, // The client trust failed or is not implemented
            KDC_ERR_KDC_NOT_TRUSTED = 0x3F, // The KDC server trust failed or could not be verified
            KDC_ERR_INVALID_SIG = 0x40, // The signature is invalid
            KDC_ERR_KEY_TOO_WEAK = 0x41, //A higher encryption level is needed
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x42, // User-to-user authorization is required
            KRB_AP_ERR_NO_TGT = 0x43, // No TGT was presented or available
            KDC_ERR_WRONG_REALM = 0x44, //Incorrect domain or principal
            KDC_ERR_CANT_VERIFY_CERTIFICATE = 0x46,
            KDC_ERR_INVALID_CERTIFICATE = 0x47,
            KDC_ERR_REVOKED_CERTIFICATE = 0x48,
            KDC_ERR_REVOCATION_STATUS_UNKNOWN = 0x49,
            KDC_ERR_CLIENT_NAME_MISMATCH = 0x4B,
            KDC_ERR_INCONSISTENT_KEY_PURPOSE = 0x4D,
            KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = 0x4E,
            KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = 0x4F,
            KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = 0x50,
            KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = 0x51,
            SUCCESS = 0xFE,
            UNKNOWN = 0xFF,
        }


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int DestIP, int SrcIP, [Out] byte[] pMacAddr, ref int PhyAddrLen);
    }
}
