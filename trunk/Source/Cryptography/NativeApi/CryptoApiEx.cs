using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Infotecs.Cryptography.NativeApi
{
    public static class CryptoApiEx
    {
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