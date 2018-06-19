﻿// Copyright (c) InfoTeCS JSC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;
using System.Text;
using Infotecs.Cryptography;
using Infotecs.ShellmaContracts.DataContracts;
using NLog;

namespace Infotecs.Shellma
{
    /// <summary>
    ///     Представляет команды работы со службой.
    /// </summary>
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.PerCall)]
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public sealed class ServiceProvider : IShellmaServiceProvider
    {
        private const string Container = @".\DataStore\UnitTestContainer";
        private const string ContainerPassword = "123123";
        private static readonly Logger log = LogManager.GetCurrentClassLogger();

        /// <summary>
        ///     Подсчет хэша.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <returns>Хэш.</returns>
        public string ComputeHash(string data)
        {
            log.Debug("ComputeHash: data: {0}", data);
            if (data == null)
            {
                throw new WebFaultException(HttpStatusCode.BadRequest);
            }
            byte[] dataValue = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(KeyContainer.ComputeHash(dataValue));
        }

        /// <summary>
        ///     Конвертирует строку в Hex представление
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string ConvertToHex(string data)
        {
            byte[] dataValue = Convert.FromBase64String(data);
            return HexEncoding.ToString(dataValue);
        }

        /// <summary>
        ///     Экспорт открытого ключа.
        /// </summary>
        /// <returns>Открытый ключ.</returns>
        public string ExportPublicKey()
        {
            log.Debug("ExportPublicKey: keyContainerName: {0}", Container);
            return Convert.ToBase64String(KeyContainer.ExportPublicKey(Container));
        }

        /// <summary>
        ///     Подпись хэша.
        /// </summary>
        /// <param name="hash">Хэш.</param>
        /// <returns>Подпись хэша.</returns>
        public string SignHash(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
            {
                throw new WebFaultException(HttpStatusCode.BadRequest);
            }

            log.Debug("SignHash: hash: {0}, keyNumber: {1}", hash, KeyNumber.Signature);
            byte[] hashValue = Convert.FromBase64String(hash);
            using (InternalKeyContainer keyContainer = KeyContainer.Open(Container, ContainerPassword))
            {
                byte[] signature = keyContainer.SignHash(hashValue, KeyNumber.Signature);
                return Convert.ToBase64String(signature);
            }
        }

        /// <summary>
        ///     Проверка подписи.
        /// </summary>
        /// <param name="request">Данные.</param>
        /// <returns>True - провека прошла успешно, иначе False.</returns>
        public bool VerifySignature(VerifySignatureRequest request)
        {
            log.Debug("VerifySignature: {0}", request);
            byte[] signatureValue = Convert.FromBase64String(request.Signature);
            byte[] dataValue = Encoding.UTF8.GetBytes(request.Data);
            byte[] publicKeyValue = Convert.FromBase64String(request.PublicKey);
            return KeyContainer.VerifySignature(signatureValue, dataValue, publicKeyValue);
        }

        /// <summary>
        ///     Экспорт сертификата из контейнера.
        /// </summary>
        public string ExportCertificate()
        {
            log.Debug("ExportCertificateData: keyContainerName: {0}", Container);
            return Convert.ToBase64String(KeyContainer.ExportCertificateData(Container));
        }

        /// <summary>
        ///     Проверка подписи.
        /// </summary>
        /// <param name="request">Данные.</param>
        /// <returns>True - провека прошла успешно, иначе False.</returns>
        public bool VerifyCertificate(VerifySignatureCertRequest request)
        {
            log.Debug("VerifySignatureSert: {0}", request);
            byte[] signatureValue = Convert.FromBase64String(request.Signature);
            byte[] dataValue = Encoding.UTF8.GetBytes(request.Data);
            byte[] certificateValue = Convert.FromBase64String(request.Certificate);

            return KeyContainer.VerifyCertificate(signatureValue, dataValue, certificateValue);
        }
    }
}
