using Infotecs.Cryptography.Info;

namespace Infotecs.Cryptography.ProviderParams
{
    public abstract class GostProviderParams : Disposable
    {
        public abstract string GetProviderName();
        public abstract int GetProviderType();
        public abstract int GetHashAlgId();
    }
}