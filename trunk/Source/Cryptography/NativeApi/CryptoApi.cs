// Copyright (c) InfoTeCS JSC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
    
    /// <summary>
    /// DllImport функций. 
    /// </summary>
    internal static class CryptoApi
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string pszContainer,
            string pszProvider,
            int dwProvType,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptCreateHash(
            IntPtr hProv,
            int algid,
            IntPtr hKey,
            int dwFlags,
            ref IntPtr phHash
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptDestroyKey(
            IntPtr hKey
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptExportKey(
            IntPtr hKey,
            IntPtr hExpKey,
            int dwBlobType,
            int dwFlags,
            byte[] pbData,
            ref int pdwDataLen
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGenKey(
            IntPtr hProv,
            int algid,
            int dwFlags,
            ref IntPtr phKey
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGetHashParam(
            IntPtr hHash,
            int dwParam,
            byte[] pbData,
            ref int pdwDataLen,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGetUserKey(
            IntPtr hProv,
            int dwKeySpec,
            ref IntPtr phUserKey
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptHashData(
            IntPtr hHash,
            byte[] pbData,
            int dwDataLen,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptImportKey(
            IntPtr hProv,
            byte[] pbData,
            int dwDataLen,
            IntPtr hPubKey,
            int dwFlags,
            ref IntPtr phKey
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptReleaseContext(
            IntPtr hProv,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptSetHashParam(
            IntPtr hHash,
            int dwParam,
            byte[] pbData,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptSetProvParam(
            IntPtr hProv,
            int dwParam,
            byte[] pbData,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptSignHash(
            IntPtr hHash,
            int dwKeySpec,
            string sDescription,
            int dwFlags,
            byte[] pbSignature,
            ref int pdwSigLen
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptVerifySignature(
            IntPtr hHash,
            byte[] pbSignature,
            int dwSigLen,
            IntPtr hPubKey,
            string sDescription,
            int dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptGetKeyParam(
            IntPtr hKey,
            uint dwParam,
            byte[] pbData,
            ref uint pdwDataLen,
            uint dwFlags
            );

        [DllImport("crypt32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertCreateCertificateContext(
            int dwCertEncodingType,
            byte[] pbCertEncoded,
            int cbCertEncoded
            );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptImportPublicKeyInfo(
            IntPtr hCryptProv,
            Int32 dwCertEncodingType,
            IntPtr pInfo,
            ref IntPtr phKey
            );
    }
}
