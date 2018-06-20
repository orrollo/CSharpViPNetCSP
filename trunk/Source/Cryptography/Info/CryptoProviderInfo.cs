using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography.Info
{
    //public class CryptoProviderInfo : List<CryptoProviderInfo.AlgInfo>
    //{
    //    public override string ToString()
    //    {
    //        return string.Format("{0} ({1}): {2} item(s)", ProviderName, ProviderType, Count);
    //    }

    //    private readonly List<string[]> _signatureAlgos = new List<string[]>();

    //    public ReadOnlyCollection<string[]> SignatureAlgos { get { return _signatureAlgos.AsReadOnly(); } }

    //    public new void Add(CryptoProviderInfo.AlgInfo item)
    //    {
    //        base.Add(item);
    //        var algClass = item.GetAlgClass();
    //        if (algClass == CryptoApiEx.AlgClass.Hash)
    //        {
    //            var signAlgos = this.Where(x => x.GetAlgClass() == CryptoApiEx.AlgClass.Signature).ToList();
    //            foreach (var signAlgo in signAlgos) CheckForSignatureGroup(item, signAlgo);
    //        }
    //        else if (algClass == CryptoApiEx.AlgClass.Signature)
    //        {
    //            var hashAlgos = this.Where(x => x.GetAlgClass() == CryptoApiEx.AlgClass.Hash).ToList();
    //            foreach (var hashAlgo in hashAlgos) CheckForSignatureGroup(hashAlgo, item);
    //        }
    //    }

    //    private void CheckForSignatureGroup(AlgInfo hashAlgo, AlgInfo signAlgo)
    //    {
    //        int[] algIds = new[] { hashAlgo.AlgId, signAlgo.AlgId };
    //        var ptr = CryptoApiEx.CryptFindOIDInfo(CryptoApiEx.CRYPT_OID_INFO_SIGN_KEY, algIds, CryptoApiEx.CRYPT_SIGN_ALG_OID_GROUP_ID);
    //        if (ptr == IntPtr.Zero) return;
    //        var oidInfo = (CryptoApiEx.CRYPT_OID_INFO)Marshal.PtrToStructure(ptr, typeof(CryptoApiEx.CRYPT_OID_INFO));
    //        var oid = Marshal.PtrToStringAnsi(oidInfo.pszOID);
    //        _signatureAlgos.Add(new[] { oid, hashAlgo.Oid, signAlgo.Oid });
    //    }

    //    //public List<string[]> GetAlgosOidGroups()
    //    //{
    //    //    var ret = new List<string[]>();

    //    //    var signAlgos = this.Where(x => x.GetAlgClass() == CryptoApiEx.AlgClass.Signature).ToList();
    //    //    var hashAlgos = this.Where(x => x.GetAlgClass() == CryptoApiEx.AlgClass.Hash).ToList();

    //    //    foreach (var signAlgo in signAlgos)
    //    //    {
    //    //        foreach (var hashAlgo in hashAlgos)
    //    //        {
    //    //            int[] algIds = new[] { hashAlgo.AlgId, signAlgo.AlgId };
    //    //            var ptr = CryptoApiEx.CryptFindOIDInfo(CryptoApiEx.CRYPT_OID_INFO_SIGN_KEY, algIds, CryptoApiEx.CRYPT_SIGN_ALG_OID_GROUP_ID);
    //    //            if (ptr == IntPtr.Zero) continue;
    //    //            var oidInfo = (CryptoApiEx.CRYPT_OID_INFO)Marshal.PtrToStructure(ptr, typeof(CryptoApiEx.CRYPT_OID_INFO));
    //    //            var oid = Marshal.PtrToStringAnsi(oidInfo.pszOID);

    //    //            ret.Add(new [] { oid, hashAlgo.Oid, signAlgo.Oid });
    //    //        }

    //    //        //var signatureOid = signAlgo.Oid;
    //    //        //if (string.IsNullOrEmpty(signatureOid)) continue;

    //    //        //cur.Clear();
    //    //        //for (uint groupId = CryptoApiEx.CRYPT_FIRST_ALG_OID_GROUP_ID;
    //    //        //    groupId <= CryptoApiEx.CRYPT_LAST_ALG_OID_GROUP_ID;
    //    //        //    groupId++)
    //    //        //{
    //    //        //    var ptr = CryptoApiEx.CryptFindOIDInfo(CryptoApiEx.CRYPT_OID_INFO_OID_KEY, signatureOid, groupId);
    //    //        //    if (ptr == IntPtr.Zero)
    //    //        //    {
    //    //        //        cur.Add(string.Empty);
    //    //        //        continue;
    //    //        //    }
    //    //        //    var oidInfo = (CryptoApiEx.CRYPT_OID_INFO)Marshal.PtrToStructure(ptr, typeof(CryptoApiEx.CRYPT_OID_INFO));
    //    //        //    var algId = oidInfo.Algid;
    //    //        //    IntPtr oidPtr = CryptoApiEx.CertAlgIdToOID(algId);
    //    //        //    var oid = Marshal.PtrToStringAnsi(oidPtr);
    //    //        //    cur.Add(oid);
    //    //        //}

    //    //    }
    //    //    return ret;
    //    //}

    //    public class AlgInfo
    //    {
    //        public int AlgId { get; protected set; }
    //        public string Oid { get; internal set; }
    //        public string Name { get; protected set; }

    //        public AlgInfo(int algId, string oid, string name, int protocols, int minLen, int maxLen)
    //        {
    //            AlgId = algId;
    //            Name = name;
    //            Oid = oid;
    //            Protocols = (CryptoApiEx.Protocols)protocols;
    //            MinLen = minLen;
    //            MaxLen = maxLen;
    //        }

    //        public int MaxLen { get; protected set; }

    //        public int MinLen { get; protected set; }

    //        public CryptoApiEx.Protocols Protocols { get; protected set; }

    //        public override string ToString()
    //        {
    //            return string.Format("{0} alg:{1} oid:{2}; class: {3}", Name, AlgId, Oid, GetAlgClass());
    //        }

    //        public CryptoApiEx.AlgClass GetAlgClass()
    //        {
    //            return CryptoApiEx.GetAlgClass(AlgId);
    //        }
    //    }

    //    public string ProviderName { get; protected set; }
    //    public int ProviderType { get; protected set; }

    //    public CryptoProviderInfo(string providerName, int providerType)
    //    {
    //        ProviderName = providerName;
    //        ProviderType = providerType;
    //    }

    //    public bool ContainsAlgId(int algId)
    //    {
    //        return this.Count(x => x.AlgId == algId) > 0;
    //    }

    //    public bool ContainsOid(string oid)
    //    {
    //        return this.Count(x => x.Oid == oid) > 0;
    //    }

    //    public AlgInfo[] FindByAlgId(int algId)
    //    {
    //        return this.Where(x => x.AlgId == algId).ToArray();
    //    }

    //    public AlgInfo[] FindByOid(string oid)
    //    {
    //        return this.Where(x => x.Oid == oid).ToArray();
    //    }
    //}
}