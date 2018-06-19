namespace Infotecs.Cryptography.ProviderParams
{
    public abstract class GostProviderParams
    {
        public abstract string GetProviderName();
        public abstract int GetProviderType();
        public abstract int GetHashAlgId();
    }
}