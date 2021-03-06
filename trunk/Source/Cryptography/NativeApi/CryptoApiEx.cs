using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Infotecs.Cryptography.NativeApi
{
    public static class CryptoApiEx
    {
        public const uint CRYPT_OID_INFO_SIGN_KEY = 4;
        public const uint CRYPT_OID_INFO_ALGID_KEY = 3;
        public const uint CRYPT_OID_INFO_OID_KEY = 1;
        //public const uint CRYPT_SIGN_ALG_OID_GROUP_ID = 4;

        public const uint CRYPT_HASH_ALG_OID_GROUP_ID = 1;
        public const uint CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2;
        public const uint CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3;
        public const uint CRYPT_SIGN_ALG_OID_GROUP_ID = 4;
        public const uint CRYPT_RDN_ATTR_OID_GROUP_ID = 5;
        public const uint CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6;
        public const uint CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7;
        public const uint CRYPT_POLICY_OID_GROUP_ID = 8;
        public const uint CRYPT_LAST_OID_GROUP_ID = 8;

        public const uint CRYPT_FIRST_ALG_OID_GROUP_ID = CRYPT_HASH_ALG_OID_GROUP_ID;
        public const uint CRYPT_LAST_ALG_OID_GROUP_ID = CRYPT_SIGN_ALG_OID_GROUP_ID;

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CryptFindOIDInfo(
            uint dwKeyType,
            [MarshalAs(UnmanagedType.LPStr)] String szOID,
            uint dwGroupId
            );

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CryptFindOIDInfo(
            uint dwKeyType,
            [MarshalAs(UnmanagedType.LPArray)] int[] algIds,
            uint dwGroupId
            );

        [DllImport("advapi32.dll", EntryPoint = "CryptEnumProviders", SetLastError = true)]
        public static extern bool CryptEnumProviders(
            Int32 dwIndex,
            IntPtr pdwReserved,
            UInt32 dwFlags,
            ref Int32 pdwProvType,
            StringBuilder pszProvName,
            ref int pcbProvName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
            IntPtr hProv,
            uint dwParam,
            IntPtr pbData,
            ref int dwDataLen,
            uint dwFlags);

        [DllImport("Crypt32.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Winapi)]
        public static extern IntPtr CertAlgIdToOID(int dwAlgId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CryptEnumProviderTypes(
            uint dwIndex,
            uint pdwReserved,
            uint dwFlags,
            ref uint pdwProvType,
            StringBuilder pszTypeName,
            ref uint pcbTypeName
            );

        [StructLayout(LayoutKind.Sequential)]
        public struct PROV_ENUMALGS_EX
        {
            public Int32 aiAlgid;
            public Int32 dwDefaultLen;
            public Int32 dwMinLen;
            public Int32 dwMaxLen;
            public Int32 dwProtocols;
            public Int32 dwNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
            public string szName;
            public Int32 dwLongNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)]
            public string szLongName;
        }

        [Flags]
        public enum AlgClass : int
        {
            Any = 0,
            Signature = 8192,
            MsgEncrypt = 16384,
            DataEncrypt = 24576,
            Hash = 32768,
            KeyExchange = 40960
        }

        [Flags]
        public enum AlgType : int
        {
            Any = 0,
            Dss =512,
            Rsa =1024,
            Block =1536,
            Stream  =2048
        }

        public static AlgClass GetAlgClass(int algId)
        {
            return (AlgClass)(algId & 57344);
        }

        public static AlgType GetAlgType(int algId)
        {
            return (AlgType)(algId & 7680);
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_OID_INFO
        {
            public uint cbSize;
            public IntPtr pszOID;
            public IntPtr pwszName;
            public uint dwGroupId;
            public int Algid;
            public CRYPT_DATA_BLOB ExtraInfo;
            public IntPtr pwszCNGAlgid;
            public IntPtr pwszCNGExtraAlgid;
        };


        [Flags]
        public enum Protocols : int
        {
            CRYPT_FLAG_IPSEC = 0x10,
            CRYPT_FLAG_PCT1 = 0x1,
            CRYPT_FLAG_SIGNING = 0x20,
            CRYPT_FLAG_SSL2 = 0x2,
            CRYPT_FLAG_SSL3 = 0x4,
            CRYPT_FLAG_TLS1 = 0x8
        }
    }
}