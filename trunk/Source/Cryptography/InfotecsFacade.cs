// Copyright (c) InfoTeCS JSC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Infotecs.Cryptography.NativeApi;

namespace Infotecs.Cryptography
{
    public class InfotecsProviderParams
    {
        public string ProviderName { get; protected set; }
        public int ProviderType { get; protected set; }

        public InfotecsProviderParams()
        {
            ProviderName = "Infotecs Cryptographic Service Provider";
            ProviderType = 2;
        }
    }

    public class GostKeyContainer : Disposable
    {
        protected InfotecsProviderParams ProviderParams;

        public GostKeyContainer(InfotecsProviderParams providerParams)
        {
            this.ProviderParams = providerParams;
        }

        public byte[] intComputeHash(byte[] data)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(null,Constants.CryptVerifycontext);
                using (HashContext hashContext = container.CreateHash(null, Constants.CpcspHashId, 0))
                {
                    hashContext.AddData(data, 0);
                    return hashContext.GetValue();
                }
            }
        }

        public  InfotecsFacade intCreate(
            string keyContainerName,
            KeyNumber keyNumber)
        {
            var container = new InfotecsFacade(ProviderParams);
            container.AcquireContext(keyContainerName,Constants.NewKeySet);
            container.GenerateRandomKey(keyNumber);
            return container;
        }

        public  byte[] intExportPublicKey(string keyContainerName)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(keyContainerName, 0);
                return container.ExportPublicKey();
            }
        }

        public  byte[] intExportCertificateData(string keyContainerName)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(keyContainerName, 0);
                return container.ExportCertificateData();
            }
        }

        public  bool intExist(string keyContainerName)
        {
            try
            {
                using (var container = new InfotecsFacade(ProviderParams))
                {
                    container.AcquireContext(keyContainerName,Constants.SilentMode);
                    container.GetUserKey();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public InfotecsFacade intOpen(
            string keyContainerName,
            string keycontainerPassword)
        {
            var container = new InfotecsFacade(ProviderParams);
            container.AcquireContext(keyContainerName, 0);
            container.SetPassword(keycontainerPassword);
            return container;
        }

        public void intRemove(string keyContainerName)
        {
            try
            {
                var container = new InfotecsFacade(ProviderParams);
                container.AcquireContext(keyContainerName,Constants.DeleteKeySet);
            }
            catch (Win32Exception)
            {
            }
        }

        public bool intVerifySignature(
            byte[] signature,
            byte[] data,
            byte[] publicKey)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = container.ImportKey(null, publicKey, 0))
                {
                    using (HashContext hashContext =
                        container.CreateHash(null, Constants.CpcspHashId, 0))
                    {
                        hashContext.AddData(data, 0);
                        return keyContext.VerifySignature(signature, hashContext, 0);
                    }
                }
            }
        }

        public bool intVerifyCertificate(
            byte[] signature,
            byte[] data,
            byte[] certificateData)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = container.ImportSertificate(certificateData))
                {
                    using (HashContext hashContext =
                        container.CreateHash(null, Constants.CpcspHashId, 0))
                    {
                        hashContext.AddData(data, 0);
                        return keyContext.VerifySignature(signature, hashContext, 0);
                    }
                }
            }
        }

        public byte[] intGetCertificatePublicKey(byte[] certificateData)
        {
            using (var container = new InfotecsFacade(ProviderParams))
            {
                container.AcquireContext(null,Constants.CryptVerifycontext);
                using (KeyContext keyContext = container.ImportSertificate(certificateData))
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

    public abstract class Disposable : IDisposable
    {
        protected bool Disposed = false;

        public void Dispose()
        {
            if (Disposed) return;
            lock (this)
            {
                if (Disposed) return;
                DoDispose();
                Disposed = true;
            }
        }

        protected abstract void DoDispose();
    }

    public class Gost2001KeyContainer
    {
        static readonly InfotecsProviderParams infotecsProviderParams = new InfotecsProviderParams();

        /// <summary>
        ///     Подсчет хэша.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <returns>Хэш.</returns>
        public static byte[] ComputeHash(byte[] data)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intComputeHash(data);
            }
        }

        /// <summary>
        ///     Создать <see cref="InfotecsFacade" />.
        /// </summary>
        /// <param name="keyContainerName">Название ключевого контейнера.</param>
        /// <param name="keyNumber">Тип ключа.</param>
        /// <returns>
        ///     Экземпляр <see cref="InfotecsFacade" />.
        /// </returns>
        public static InfotecsFacade Create(string keyContainerName, KeyNumber keyNumber)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intCreate(keyContainerName, keyNumber);
            }
        }

        /// <summary>
        ///     Экспорт открытого ключа.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>Открытый ключ.</returns>
        public static byte[] ExportPublicKey(string keyContainerName)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intExportPublicKey(keyContainerName);
            }
        }

        /// <summary>
        ///     Получить сертификат для конкретного ключа
        /// </summary>
        /// <returns></returns>
        public static byte[] ExportCertificateData(string keyContainerName)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intExportCertificateData(keyContainerName);
            }
        }

        /// <summary>
        ///     Провекра наличия контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>True - контейнер существует, иначе False.</returns>
        public static bool Exist(string keyContainerName)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intExist(keyContainerName);
            }
        }

        /// <summary>
        ///     Открыть существующий контейнер.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <param name="keycontainerPassword">Пароль ключевого контейнера.</param>
        /// <returns>
        ///     Экземпляр <see cref="InfotecsFacade" />.
        /// </returns>
        public static InfotecsFacade Open(string keyContainerName, string keycontainerPassword)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intOpen(keyContainerName, keycontainerPassword);
            }
        }

        /// <summary>
        ///     Удаление ключевого контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        public static void Remove(string keyContainerName)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                kk.intRemove(keyContainerName);
            }
        }

        /// <summary>
        ///     Проверка подписи.
        /// </summary>
        /// <param name="signature">Подпись.</param>
        /// <param name="data">Данные.</param>
        /// <param name="publicKey">Открытый ключ.</param>
        /// <returns>True - провека прошла успешно, иначе False.</returns>
        public static bool VerifySignature(byte[] signature, byte[] data, byte[] publicKey)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intVerifySignature(signature, data, publicKey);
            }
        }

        /// <summary>
        ///     Проверка подписи.
        /// </summary>
        /// <param name="signature">Подпись.</param>
        /// <param name="data">Данные.</param>
        /// <param name="certificateData">Сертификат.</param>
        /// <returns>True - провека прошла успешно, иначе False.</returns>
        public static bool VerifyCertificate(byte[] signature, byte[] data, byte[] certificateData)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intVerifyCertificate(signature, data, certificateData);
            }
        }

        /// <summary>
        /// Возвращает открытый ключ сертификата
        /// </summary>
        /// <param name="certificateData">данные сертификата</param>
        /// <returns></returns>
        public static byte[] GetCertificatePublicKey(byte[] certificateData)
        {
            var providerParams = infotecsProviderParams;
            using (var kk = new GostKeyContainer(providerParams))
            {
                return kk.intGetCertificatePublicKey(certificateData);
            }
        }
    }

    /// <summary>
    ///     Класс представляет функциональность Infotecs криптопровайдера.
    /// </summary>
    public class InfotecsFacade : IDisposable
    {
        private const int PpSignaturePin = 0x21;

        private IntPtr cspHandler = IntPtr.Zero;
        private bool disposed;

        protected InfotecsProviderParams ProviderParams;

        /// <summary>
        ///     Конструктор.
        /// </summary>
        internal InfotecsFacade(InfotecsProviderParams providerParams)
        {
            this.ProviderParams = providerParams;
        }

        /// <summary>
        ///     Экспорт открытого ключа.
        /// </summary>
        /// <returns>Открытый ключ.</returns>
        public byte[] ExportPublicKey()
        {
            using (KeyContext keyContext = GetUserKey())
            {
                return keyContext.ExportPublicKey();
            }
        }

        /// <summary>
        ///     Получить сертификат для конкретного ключа
        /// </summary>
        /// <returns></returns>
        public byte[] ExportCertificateData()
        {
            using (KeyContext keyContext = GetUserKey())
            {
                var rawDataCertificate = keyContext.GetSertificateData();
                return rawDataCertificate;
            }
        }

        /// <summary>
        ///     Подпись хэша.
        /// </summary>
        /// <param name="hash">Хэш.</param>
        /// <param name="keyNumber">Тип ключа.</param>
        /// <returns>Подпись хэша.</returns>
        public byte[] SignHash(byte[] hash, KeyNumber keyNumber)
        {
            using (HashContext hashContext = CreateHash(null, Constants.CpcspHashId, 0))
            {
                hashContext.SetHashParameter(Constants.HpHashValue, hash, 0);
                return hashContext.SignHash(keyNumber, 0);
            }
        }

        /// <summary>
        ///     Освобождает ресурсы.
        /// </summary>
        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            if (cspHandler != IntPtr.Zero)
            {
                CryptoApi.CryptReleaseContext(cspHandler, 0);
                cspHandler = IntPtr.Zero;
            }
            disposed = true;
        }

        internal void AcquireContext(string keyContainerName, int flags)
        {
            Dispose();

            if (!CryptoApi.CryptAcquireContext(ref cspHandler, keyContainerName, ProviderParams.ProviderName, ProviderParams.ProviderType, flags))
            {
                throw new Win32Exception();
            }
        }

        internal HashContext CreateHash(KeyContext keyContext, int algid, int flags)
        {
            IntPtr hashHandler = IntPtr.Zero;
            IntPtr keyHandler = IntPtr.Zero;

            if (keyContext != null)
            {
                keyHandler = keyContext.Handler;
            }

            if (!CryptoApi.CryptCreateHash(cspHandler, algid, keyHandler, flags, ref hashHandler))
            {
                throw new Win32Exception();
            }

            var hashContext = new HashContext(hashHandler);
            return hashContext;
        }

        internal KeyContext GenerateRandomKey(KeyNumber keyNumber, int flags = 0)
        {
            IntPtr keyPiarHandler = IntPtr.Zero;
            if (!CryptoApi.CryptGenKey(cspHandler, (int)keyNumber, flags, ref keyPiarHandler))
            {
                throw new Win32Exception();
            }

            var keyPairContext = new KeyContext(keyPiarHandler);
            return keyPairContext;
        }

        internal KeyContext GetUserKey(int keySpec = 0)
        {
            IntPtr keyPiarHandler = IntPtr.Zero;
            if (!CryptoApi.CryptGetUserKey(cspHandler, keySpec, ref keyPiarHandler))
            {
                throw new Win32Exception();
            }

            var keyPairContext = new KeyContext(keyPiarHandler);
            return keyPairContext;
        }

        internal KeyContext ImportKey(KeyContext protectionKeyContext, byte[] keyData, int flags)
        {
            IntPtr protectionKeyHandler = IntPtr.Zero;

            if (protectionKeyContext != null)
            {
                protectionKeyHandler = protectionKeyContext.Handler;
            }

            IntPtr keyHandler = IntPtr.Zero;
            if (!CryptoApi.CryptImportKey(cspHandler, keyData, keyData.Length,
                protectionKeyHandler, flags, ref keyHandler))
            {
                throw new Win32Exception();
            }

            var keyContext = new KeyContext(keyHandler);
            return keyContext;
        }

        internal KeyContext ImportSertificate(byte[] certificateData)
        {
            // создаём объект сертификата
            var hCertContext = CryptoApi.CertCreateCertificateContext(
                Constants.MyEncodingType, certificateData, certificateData.Length);

            //Получаем указатель на SubjectPublicKeyInfo
            var certContextStruct = (Constants.CertContext)
                Marshal.PtrToStructure(hCertContext, typeof(Constants.CertContext));
            var pCertInfo = certContextStruct.pCertInfo;

            // магия. для x32 и x64 сборок структуры разных размеров
            var certInfoStruct = (Constants.CertInfo)Marshal.PtrToStructure(pCertInfo, typeof(Constants.CertInfo));
            IntPtr subjectPublicKeyInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certInfoStruct.SubjectPublicKeyInfo));
            Marshal.StructureToPtr(certInfoStruct.SubjectPublicKeyInfo, subjectPublicKeyInfo, false);

            IntPtr keyHandler = IntPtr.Zero;
            if (!CryptoApi.CryptImportPublicKeyInfo(cspHandler, Constants.MyEncodingType,
                subjectPublicKeyInfo, ref keyHandler))
            {
                throw new Win32Exception();
            }

            var keyContext = new KeyContext(keyHandler);
            return keyContext;
        }

        internal void SetPassword(string password)
        {
            byte[] pwdData = Encoding.ASCII.GetBytes(password);
            var pwdDataWithEndZero = new byte[pwdData.Length + 1];
            Array.Copy(pwdData, pwdDataWithEndZero, pwdData.Length);
            SetProviderParameter(PpSignaturePin, pwdDataWithEndZero);
        }

        private void SetProviderParameter(int parameterId, byte[] parameterValue)
        {
            if (!CryptoApi.CryptSetProvParam(cspHandler, parameterId, parameterValue, 0))
            {
                throw new Win32Exception();
            }
        }
    }
}
