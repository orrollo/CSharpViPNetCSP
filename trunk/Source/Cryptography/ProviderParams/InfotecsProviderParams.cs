using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography.ProviderParams
{
    public class InfotecsProviderParams : GostProviderParams
    {
        protected string ProviderName;
        protected int ProviderType;

        public override string GetProviderName()
        {
            return ProviderName;
        }

        public override int GetProviderType()
        {
            return ProviderType;
        }

        public InfotecsProviderParams()
        {
            ProviderName = "Infotecs Cryptographic Service Provider";
            ProviderType = 2;
        }

        public override int GetHashAlgId()
        {
            return Constants.CpcspHashId;
        }
    }
}