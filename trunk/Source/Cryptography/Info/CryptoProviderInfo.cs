using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography.Info
{
    public class CryptoProviderInfo : List<CryptoProviderInfo.AlgInfo>
    {
        public override string ToString()
        {
            return string.Format("{0} ({1}): {2} item(s)", ProviderName, ProviderType, Count);
        }

        public class AlgInfo
        {
            public int AlgId { get; protected set; }
            public string Oid { get; internal set; }
            public string Name { get; protected set; }

            public AlgInfo(int algId, string oid, string name, int protocols, int minLen, int maxLen)
            {
                AlgId = algId;
                Name = name;
                Oid = oid;
                Protocols = (CryptoApiEx.Protocols)protocols;
                MinLen = minLen;
                MaxLen = maxLen;
            }

            public int MaxLen { get; protected set; }

            public int MinLen { get; protected set; }

            public CryptoApiEx.Protocols Protocols { get; protected set; }

            public override string ToString()
            {
                return string.Format("{0} alg:{1} oid:{2}; class: {3}", Name, AlgId, Oid, CryptoApiEx.GetAlgClass(AlgId).ToString());
            }
        }

        public string ProviderName { get; protected set; }
        public int ProviderType { get; protected set; }

        public CryptoProviderInfo(string providerName, int providerType)
        {
            ProviderName = providerName;
            ProviderType = providerType;
        }

        public bool ContainsAlgId(int algId)
        {
            return this.Count(x => x.AlgId == algId) > 0;
        }

        public bool ContainsOid(string oid)
        {
            return this.Count(x => x.Oid == oid) > 0;
        }

        public AlgInfo[] FindByAlgId(int algId)
        {
            return this.Where(x => x.AlgId == algId).ToArray();
        }

        public AlgInfo[] FindByOid(string oid)
        {
            return this.Where(x => x.Oid == oid).ToArray();
        }
    }
}