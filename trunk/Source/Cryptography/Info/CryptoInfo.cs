using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography.Info
{
    public static class CryptoInfo
    {
        public static List<CryptoProviderInfo> GetProviders()
        {
            var result = new List<CryptoProviderInfo>();
            var dwIndex = 0;
            int dwType = 1;
            int cbName = 0;
            while (CryptoApiEx.CryptEnumProviders(dwIndex, IntPtr.Zero, 0, ref dwType, null, ref cbName))
            {
                var pszName = new StringBuilder((int)cbName+1);
                if (CryptoApiEx.CryptEnumProviders(dwIndex++, IntPtr.Zero, 0, ref dwType, pszName, ref cbName))
                {
                    CryptoProviderInfo info = GetAllAlgosEx(pszName.ToString(), dwType);
                    result.Add(info);
                }
            }
            return result;
        }

        public static CryptoProviderInfo GetAllAlgosEx(string providerName, int providerType)
        {
            var providerInfo = new CryptoProviderInfo(providerName, providerType);

            IntPtr cspHandler = IntPtr.Zero;
            IntPtr pnt = IntPtr.Zero;
            try
            {
                if (!CryptoApi.CryptAcquireContext(ref cspHandler, null, providerName, providerType, Constants.CryptVerifycontext))
                    throw new Win32Exception();

                int dwDataLen = Marshal.SizeOf(typeof(CryptoApiEx.PROV_ENUMALGS_EX)) * 2;
                pnt = Marshal.AllocHGlobal(dwDataLen);
                uint dwFlags = 1;
                while (CryptoApiEx.CryptGetProvParam(cspHandler, Constants.PP_ENUMALGS_EX, pnt, ref dwDataLen, dwFlags))
                {
                    var data = (CryptoApiEx.PROV_ENUMALGS_EX)Marshal.PtrToStructure(pnt, typeof(CryptoApiEx.PROV_ENUMALGS_EX));
                    var oid = string.Empty; // CryptoApiEx.CertAlgIdToOID(data.aiAlgid);
                    providerInfo.Add(new CryptoProviderInfo.AlgInfo(data.aiAlgid, oid, data.szName, data.dwProtocols, data.dwMinLen, data.dwMaxLen));
                    dwFlags = 2;
                }
            }
            finally
            {
                if (pnt != IntPtr.Zero) Marshal.FreeHGlobal(pnt);
                if (cspHandler != IntPtr.Zero) CryptoApi.CryptReleaseContext(cspHandler, 0);
            }

            var reOid = new Regex("^[0-9]+([.][0-9]+)+$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            // process oids
            foreach (var info in providerInfo)
            {
                var oid = CryptoApiEx.CertAlgIdToOID(info.AlgId);
                if (string.IsNullOrEmpty(oid) || !reOid.IsMatch(oid)) oid = string.Empty;
                info.Oid = oid;
            }

            return providerInfo;
        }

    }
}