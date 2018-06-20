// Copyright (c) InfoTeCS JSC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Infotecs.Cryptography.NativeApi;
using Infotecs.Cryptography.ProviderParams;

namespace Infotecs.Cryptography
{
    /// <summary>
    ///     Класс представляет функциональность Infotecs криптопровайдера.
    /// </summary>
    public class GostCryptFacade : Disposable
    {
        private const int PpSignaturePin = 0x21;

        private IntPtr cspHandler = IntPtr.Zero;
        //private bool disposed;

        protected GostProviderParams ProviderParams;

        /// <summary>
        ///     Конструктор.
        /// </summary>
        internal GostCryptFacade(GostProviderParams providerParams)
        {
            ProviderParams = providerParams;
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
            using (HashContext hashContext = CreateHash(null, 0))
            {
                hashContext.SetHashParameter(Constants.HpHashValue, hash, 0);
                return hashContext.SignHash(keyNumber, 0);
            }
        }

        ///// <summary>
        /////     Освобождает ресурсы.
        ///// </summary>
        //public void Dispose()
        //{
        //    if (disposed)
        //    {
        //        return;
        //    }
        //    if (cspHandler != IntPtr.Zero)
        //    {
        //        CryptoApi.CryptReleaseContext(cspHandler, 0);
        //        cspHandler = IntPtr.Zero;
        //    }
        //    disposed = true;
        //}

        internal void AcquireContext(string keyContainerName, int flags)
        {
            Dispose();

            if (!CryptoApi.CryptAcquireContext(ref cspHandler, keyContainerName, ProviderParams.GetProviderName(), ProviderParams.GetProviderType(), flags))
            {
                throw new Win32Exception();
            }
        }

        internal HashContext CreateHash(KeyContext keyContext, int flags)
        {
            int algid = ProviderParams.GetHashAlgId();

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

        protected override void DoDispose()
        {
            if (cspHandler == IntPtr.Zero) return;
            CryptoApi.CryptReleaseContext(cspHandler, 0);
            cspHandler = IntPtr.Zero;
        }
    }
}
