using System.ComponentModel;
using System.Security.Cryptography;
using Infotecs.Cryptography.NativeApi;
using Infotecs.Cryptography.ProviderParams;

namespace Infotecs.Cryptography
{
    internal class GostInfotecs : Disposable
    {
        protected GostProviderParams ProviderParams;

        public GostInfotecs(GostProviderParams providerParams)
        {
            this.ProviderParams = providerParams;
        }

        public byte[] ComputeHash(byte[] data)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(null,Constants.CryptVerifycontext);
                using (HashContext hashContext = facade.CreateHash(null, 0))
                {
                    hashContext.AddData(data, 0);
                    return hashContext.GetValue();
                }
            }
        }

        public  InfotecsFacade Create(
            string keyContainerName,
            KeyNumber keyNumber)
        {
            var facade = new InfotecsFacade(ProviderParams);
            facade.AcquireContext(keyContainerName,Constants.NewKeySet);
            facade.GenerateRandomKey(keyNumber);
            return facade;
        }

        public  byte[] ExportPublicKey(string keyContainerName)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(keyContainerName, 0);
                return facade.ExportPublicKey();
            }
        }

        public  byte[] ExportCertificateData(string keyContainerName)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(keyContainerName, 0);
                return facade.ExportCertificateData();
            }
        }

        public  bool Exist(string keyContainerName)
        {
            try
            {
                using (var facade = new InfotecsFacade(ProviderParams))
                {
                    facade.AcquireContext(keyContainerName,Constants.SilentMode);
                    facade.GetUserKey();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public InfotecsFacade Open(
            string keyContainerName,
            string keycontainerPassword)
        {
            var facade = new InfotecsFacade(ProviderParams);
            facade.AcquireContext(keyContainerName, 0);
            facade.SetPassword(keycontainerPassword);
            return facade;
        }

        public void Remove(string keyContainerName)
        {
            try
            {
                var facade = new InfotecsFacade(ProviderParams);
                facade.AcquireContext(keyContainerName,Constants.DeleteKeySet);
            }
            catch (Win32Exception)
            {
            }
        }

        public bool VerifySignature(
            byte[] signature,
            byte[] data,
            byte[] publicKey)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = facade.ImportKey(null, publicKey, 0))
                {
                    using (HashContext hashContext = facade.CreateHash(null, 0))
                    {
                        hashContext.AddData(data, 0);
                        return keyContext.VerifySignature(signature, hashContext, 0);
                    }
                }
            }
        }

        public bool VerifyCertificate(
            byte[] signature,
            byte[] data,
            byte[] certificateData)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = facade.ImportSertificate(certificateData))
                {
                    using (HashContext hashContext = facade.CreateHash(null, 0))
                    {
                        hashContext.AddData(data, 0);
                        return keyContext.VerifySignature(signature, hashContext, 0);
                    }
                }
            }
        }

        public byte[] GetCertificatePublicKey(byte[] certificateData)
        {
            using (var facade = new InfotecsFacade(ProviderParams))
            {
                facade.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = facade.ImportSertificate(certificateData))
                {
                    return keyContext.ExportPublicKey();
                }
            }
        }

        protected override void DoDispose()
        {
            ProviderParams = null;
        }
    }
}