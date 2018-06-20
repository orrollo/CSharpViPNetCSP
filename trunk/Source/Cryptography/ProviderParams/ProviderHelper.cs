using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography.ProviderParams
{
    public class ProviderHelper
    {
        public class ProviderAlgoBase
        {
            private int algId;

            public int AlgId
            {
                get { return GetAlgId(); }
                internal set { SetAlgId(value); }
            }

            public string Oid { get; set; }
            public string Name { get; set; }

            protected virtual void SetAlgId(int value)
            {
                algId = value;
            }

            protected virtual int GetAlgId()
            {
                return algId;
            }
        }

        public class ProviderAlgo : ProviderAlgoBase
        {
            private CryptoApiEx.AlgClass? _class;

            public string LongName { get; internal set; }

            public int Protocols { get; internal set; }

            public int MinLen { get; internal set; }
            public int MaxLen { get; internal set; }
            public int DefaultLen { get; internal set; }

            public CryptoApiEx.AlgClass Class
            {
                get { return (_class ?? (_class = CryptoApiEx.GetAlgClass(AlgId))).Value; }
                internal set { _class = value; }
            }

            protected override void SetAlgId(int value)
            {
                base.SetAlgId(value);
                _class = null;
            }

            public override string ToString()
            {
                return string.Format("<{0}> alg:{1} oid:{2}; class: {3}", Name, AlgId, Oid, Class);
            }
        }

        public class ProviderSignGroup : ProviderAlgoBase
        {
            public ProviderAlgo HashAlgo { get; internal set; }
            public ProviderAlgo SignAlgo { get; internal set; }
        }

        public class ProviderInfo : List<ProviderAlgo>
        {
            internal string ProviderName { get; set; }
            internal int ProviderType { get; set; }

            public bool IsCompatible(params string[] oids)
            {
                if (oids == null || oids.Length == 0) throw new ArgumentException();
                return oids.All(oid => this.Any(x => x.Oid == oid) || SignGroups.Any(x => x.Oid == oid));
            }

            public void Initialize()
            {
                var reOid = new Regex("^[0-9]+([.][0-9]+)+$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                IntPtr cspHandler = IntPtr.Zero;
                IntPtr pnt = IntPtr.Zero;
                try
                {
                    if (!CryptoApi.CryptAcquireContext(ref cspHandler, null, ProviderName, ProviderType, Constants.CryptVerifycontext))
                        throw new Win32Exception();

                    int dwDataLen = Marshal.SizeOf(typeof(CryptoApiEx.PROV_ENUMALGS_EX)) * 2;
                    pnt = Marshal.AllocHGlobal(dwDataLen);
                    uint dwFlags = 1;
                    while (CryptoApiEx.CryptGetProvParam(cspHandler, Constants.PP_ENUMALGS_EX, pnt, ref dwDataLen, dwFlags))
                    {
                        var data = (CryptoApiEx.PROV_ENUMALGS_EX)Marshal.PtrToStructure(pnt, typeof(CryptoApiEx.PROV_ENUMALGS_EX));
                        IntPtr oidPtr = CryptoApiEx.CertAlgIdToOID(data.aiAlgid);
                        var oid = Marshal.PtrToStringAnsi(oidPtr);
                        if (string.IsNullOrEmpty(oid) || !reOid.IsMatch(oid)) oid = string.Empty;
                        this.Add(new ProviderAlgo()
                        {
                            AlgId = data.aiAlgid,
                            Oid = oid,
                            Name = data.szName,
                            LongName = data.szLongName,
                            MinLen = data.dwMinLen,
                            MaxLen = data.dwMaxLen,
                            DefaultLen = data.dwDefaultLen,
                            Protocols = data.dwProtocols
                        });
                        dwFlags = 2;
                    }
                }
                finally
                {
                    if (pnt != IntPtr.Zero) Marshal.FreeHGlobal(pnt);
                    if (cspHandler != IntPtr.Zero) CryptoApi.CryptReleaseContext(cspHandler, 0);
                }
                
            }

            public new void Add(ProviderAlgo item)
            {
                base.Add(item);
                //
                if (item.Class == CryptoApiEx.AlgClass.Hash)
                {
                    var signAlgos = this.Where(x => x.Class == CryptoApiEx.AlgClass.Signature).ToList();
                    foreach (var signAlgo in signAlgos) LookForSignatureGroup(item, signAlgo);
                }
                else if (item.Class == CryptoApiEx.AlgClass.Signature)
                {
                    var hashAlgos = this.Where(x => x.Class == CryptoApiEx.AlgClass.Hash).ToList();
                    foreach (var hashAlgo in hashAlgos) LookForSignatureGroup(hashAlgo, item);
                }
            }

            public List<ProviderSignGroup> SignGroups = new List<ProviderSignGroup>();

            private void LookForSignatureGroup(ProviderAlgo hashAlgo, ProviderAlgo signAlgo)
            {
                int[] algIds = new[] { hashAlgo.AlgId, signAlgo.AlgId };
                var ptr = CryptoApiEx.CryptFindOIDInfo(CryptoApiEx.CRYPT_OID_INFO_SIGN_KEY, algIds, CryptoApiEx.CRYPT_SIGN_ALG_OID_GROUP_ID);
                if (ptr == IntPtr.Zero) return;
                var oidInfo = (CryptoApiEx.CRYPT_OID_INFO)Marshal.PtrToStructure(ptr, typeof(CryptoApiEx.CRYPT_OID_INFO));
                var oid = Marshal.PtrToStringAnsi(oidInfo.pszOID);
                //
                SignGroups.Add(new ProviderSignGroup()
                {
                    AlgId = oidInfo.Algid,
                    HashAlgo = hashAlgo,
                    SignAlgo = signAlgo,
                    Oid = oid,
                    Name = Marshal.PtrToStringUni(oidInfo.pwszName)
                });
            }
        }

        internal class ConfigurableProviderParams : GostProviderParams, IDisposable
        {
            internal ProviderInfo Info { get; set; }
            internal ProviderAlgo SignAlgo { get; set; }
            internal ProviderAlgo HashAlgo { get; set; }

            public override string GetProviderName()
            {
                return Info.ProviderName;
            }

            public override int GetProviderType()
            {
                return Info.ProviderType;
            }

            public override int GetHashAlgId()
            {
                return HashAlgo.AlgId;
            }

            protected override void DoDispose()
            {
                Info = null;
                SignAlgo = null;
                HashAlgo = null;
            }
        }

        internal static List<ProviderInfo> Providers;
        internal static object Locker = new object();

        static ProviderHelper()
        {
            EnumerateProviders();
        }

        public static GostProviderParams ParamsForPublicKeyOid(string oid)
        {
            if (string.IsNullOrEmpty(oid)) throw new ArgumentException();
            var providerInfo = Providers.FirstOrDefault(x => x.SignGroups.Any(y => y.SignAlgo.Oid == oid));
            if (providerInfo == null) return null;
            var signGroup = providerInfo.SignGroups.First(x => x.SignAlgo.Oid == oid);
            var result = new ConfigurableProviderParams()
            {
                Info = providerInfo,
                SignAlgo = signGroup.SignAlgo,
                HashAlgo = signGroup.HashAlgo
            };
            return result;
        }

        public static bool IsCompatible(string oid)
        {
            if (string.IsNullOrEmpty(oid)) throw new ArgumentException();
            return Providers.Any(x => x.SignGroups.Any(y => y.Oid == oid)) || Providers.Any(x => x.Any(y => y.Oid == oid));
        }

        public static GostProviderParams ParamsForSignAlgoOid(string oid)
        {
            if (string.IsNullOrEmpty(oid)) throw new ArgumentException();
            var providerInfo = Providers.FirstOrDefault(x => x.SignGroups.Any(y => y.Oid == oid));
            if (providerInfo == null) return null;
            var signGroup = providerInfo.SignGroups.First(x => x.Oid == oid);
            var result = new ConfigurableProviderParams()
            {
                Info = providerInfo,
                SignAlgo = signGroup.SignAlgo,
                HashAlgo = signGroup.HashAlgo
            };
            return result;
        }

        public static GostProviderParams ParamsForOids(params string[] oids)
        {
            if (oids == null || oids.Length == 0) throw new ArgumentException();
            var providerInfo = Providers.FirstOrDefault(x => x.IsCompatible(oids));
            if (providerInfo == null) return null;
            ProviderAlgo signAlgo = null, hashAlgo = null;
            foreach (var oid in oids)
            {
                var algo = providerInfo.FirstOrDefault(x => x.Oid == oid);
                if (algo != null)
                {
                    if (algo.Class == CryptoApiEx.AlgClass.Hash) hashAlgo = algo;
                    if (algo.Class == CryptoApiEx.AlgClass.Signature) signAlgo = algo;
                }
                else
                {
                    var sign = providerInfo.SignGroups.First(x => x.Oid == oid);
                    signAlgo = signAlgo ?? sign.SignAlgo;
                    hashAlgo = hashAlgo ?? sign.HashAlgo;
                }
                if (hashAlgo != null && signAlgo != null) break;
            }
            //
            if (hashAlgo == null && signAlgo == null) return null;
            //
            var result = new ConfigurableProviderParams()
            {
                Info = providerInfo,
                SignAlgo = signAlgo,
                HashAlgo = hashAlgo
            };
            return result;
        }

        public static IEnumerable<ProviderInfo> ProviderInfos
        {
            get { return Providers.AsReadOnly(); }
        }

        private static void EnumerateProviders()
        {
            if (Providers != null) return;
            lock (Locker)
            {
                if (Providers != null) return;
                Providers = new List<ProviderInfo>();
                var dwIndex = 0;
                int dwType = 1;
                int cbName = 0;
                while (CryptoApiEx.CryptEnumProviders(dwIndex, IntPtr.Zero, 0, ref dwType, null, ref cbName))
                {
                    var pszName = new StringBuilder((int)cbName + 1);
                    if (!CryptoApiEx.CryptEnumProviders(dwIndex++, IntPtr.Zero, 0, ref dwType, pszName, ref cbName)) continue;
                    Providers.Add(new ProviderInfo()
                    {
                        ProviderType = dwType,
                        ProviderName = pszName.ToString()
                    });
                }
                foreach (var providerInfo in Providers) providerInfo.Initialize();
            }
        }
    }
}