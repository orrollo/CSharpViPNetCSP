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
    public class Gost2001ProviderParams
    {
        public string ProviderName { get; protected set; }
        public int ProviderType { get; protected set; }

        public Gost2001ProviderParams()
        {
            ProviderName = "Infotecs Cryptographic Service Provider";
            ProviderType = 2;
        }
    }

    public class GostKeyContainer
    {
        public static byte[] intComputeHash(byte[] data, Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(
                    null,
                    providerParams.ProviderName,
                    providerParams.ProviderType,
                    Constants.CryptVerifycontext);
                using (HashContext hashContext = container.CreateHash(null, Constants.CpcspHashId, 0))
                {
                    hashContext.AddData(data, 0);
                    return hashContext.GetValue();
                }
            }
        }

        public static InternalKeyContainer intCreate(
            string keyContainerName,
            KeyNumber keyNumber,
            Gost2001ProviderParams providerParams)
        {
            var container = new InternalKeyContainer();
            container.AcquireContext(keyContainerName,providerParams.ProviderName,providerParams.ProviderType,Constants.NewKeySet);
            container.GenerateRandomKey(keyNumber);
            return container;
        }

        public static byte[] intExportPublicKey(string keyContainerName, Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(keyContainerName, providerParams.ProviderName, providerParams.ProviderType, 0);
                return container.ExportPublicKey();
            }
        }

        public static byte[] intExportCertificateData(string keyContainerName, Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(keyContainerName, providerParams.ProviderName, providerParams.ProviderType, 0);
                return container.ExportCertificateData();
            }
        }

        public static bool intExist(string keyContainerName, Gost2001ProviderParams providerParams)
        {
            try
            {
                using (var container = new InternalKeyContainer())
                {
                    container.AcquireContext(
                        keyContainerName,
                        providerParams.ProviderName,
                        providerParams.ProviderType,
                        Constants.SilentMode);
                    container.GetUserKey();
                    return true;
                }
            }
            catch (Win32Exception)
            {
                return false;
            }
        }

        public static InternalKeyContainer intOpen(
            string keyContainerName,
            string keycontainerPassword,
            Gost2001ProviderParams providerParams)
        {
            var container = new InternalKeyContainer();
            container.AcquireContext(keyContainerName, providerParams.ProviderName, providerParams.ProviderType, 0);
            container.SetPassword(keycontainerPassword);
            return container;
        }

        public static void intRemove(string keyContainerName, Gost2001ProviderParams providerParams)
        {
            try
            {
                var container = new InternalKeyContainer();
                container.AcquireContext(
                    keyContainerName,
                    providerParams.ProviderName,
                    providerParams.ProviderType,
                    Constants.DeleteKeySet);
            }
            catch (Win32Exception)
            {
            }
        }

        public static bool intVerifySignature(
            byte[] signature,
            byte[] data,
            byte[] publicKey,
            Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(
                    null,
                    providerParams.ProviderName,
                    providerParams.ProviderType,
                    Constants.CryptVerifycontext);
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

        public static bool intVerifyCertificate(
            byte[] signature,
            byte[] data,
            byte[] certificateData,
            Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(
                    null,
                    providerParams.ProviderName,
                    providerParams.ProviderType,
                    Constants.CryptVerifycontext);
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

        public static byte[] intGetCertificatePublicKey(byte[] certificateData, Gost2001ProviderParams providerParams)
        {
            using (var container = new InternalKeyContainer())
            {
                container.AcquireContext(
                    null,
                    providerParams.ProviderName,
                    providerParams.ProviderType,
                    Constants.CryptVerifycontext);
                using (KeyContext keyContext = container.ImportSertificate(certificateData))
                {
                    return keyContext.ExportPublicKey();
                }
            }
        }
    }

    public class Gost2001KeyContainer
    {
        static readonly Gost2001ProviderParams gost2001ProviderParams = new Gost2001ProviderParams();

        /// <summary>
        ///     Подсчет хэша.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <returns>Хэш.</returns>
        public static byte[] ComputeHash(byte[] data)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intComputeHash(data, providerParams);
        }

        /// <summary>
        ///     Создать <see cref="InternalKeyContainer" />.
        /// </summary>
        /// <param name="keyContainerName">Название ключевого контейнера.</param>
        /// <param name="keyNumber">Тип ключа.</param>
        /// <returns>
        ///     Экземпляр <see cref="InternalKeyContainer" />.
        /// </returns>
        public static InternalKeyContainer Create(string keyContainerName, KeyNumber keyNumber)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intCreate(keyContainerName, keyNumber, providerParams);
        }

        /// <summary>
        ///     Экспорт открытого ключа.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>Открытый ключ.</returns>
        public static byte[] ExportPublicKey(string keyContainerName)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intExportPublicKey(keyContainerName, providerParams);
        }

        /// <summary>
        ///     Получить сертификат для конкретного ключа
        /// </summary>
        /// <returns></returns>
        public static byte[] ExportCertificateData(string keyContainerName)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intExportCertificateData(keyContainerName, providerParams);
        }

        /// <summary>
        ///     Провекра наличия контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>True - контейнер существует, иначе False.</returns>
        public static bool Exist(string keyContainerName)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intExist(keyContainerName, providerParams);
        }

        /// <summary>
        ///     Открыть существующий контейнер.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <param name="keycontainerPassword">Пароль ключевого контейнера.</param>
        /// <returns>
        ///     Экземпляр <see cref="InternalKeyContainer" />.
        /// </returns>
        public static InternalKeyContainer Open(string keyContainerName, string keycontainerPassword)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intOpen(keyContainerName, keycontainerPassword, providerParams);
        }

        /// <summary>
        ///     Удаление ключевого контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        public static void Remove(string keyContainerName)
        {
            var providerParams = gost2001ProviderParams;
            GostKeyContainer.intRemove(keyContainerName, providerParams);
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
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intVerifySignature(signature, data, publicKey, providerParams);
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
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intVerifyCertificate(signature, data, certificateData, providerParams);
        }

        /// <summary>
        /// Возвращает открытый ключ сертификата
        /// </summary>
        /// <param name="certificateData">данные сертификата</param>
        /// <returns></returns>
        public static byte[] GetCertificatePublicKey(byte[] certificateData)
        {
            var providerParams = gost2001ProviderParams;
            return GostKeyContainer.intGetCertificatePublicKey(certificateData, providerParams);
        }
    }

    /// <summary>
    ///     Класс представляет функциональность Infotecs криптопровайдера.
    /// </summary>
    public class InternalKeyContainer : IDisposable
    {
        private const int PpSignaturePin = 0x21;

        private IntPtr cspHandler = IntPtr.Zero;
        private bool disposed;

        /// <summary>
        ///     Конструктор.
        /// </summary>
        internal InternalKeyContainer()
        {
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

        internal void AcquireContext(string keyContainerName, string providerName, int providerType, int flags)
        {
            Dispose();

            if (!CryptoApi.CryptAcquireContext(ref cspHandler, keyContainerName, providerName, providerType, flags))
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
