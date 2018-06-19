// Copyright (c) InfoTeCS JSC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text;
using Infotecs.Cryptography;
using Infotecs.Cryptography.Info;
using NUnit.Framework;

namespace UnitTests.Cryptography
{
    /// <summary>
    /// тесты для информационных функций
    /// </summary>
    [TestFixture]
    public sealed class CryptoInfoTests
    {
        [Test]
        public void GetAllAlgosEx()
        {
            var info = CryptoInfo.GetAllAlgosEx("Infotecs Cryptographic Service Provider", 2);
            Assert.AreNotEqual(info, null);
            Assert.AreNotEqual(info.Count, 0);
        }

        [Test]
        public void GetProviders()
        {
            var info = CryptoInfo.GetProviders();
            Assert.AreNotEqual(info, null);
            Assert.AreNotEqual(info.Count, 0);
        }

    }

    /// <summary>
    ///     Тесты на <see cref="InfotecsFacade" />.
    /// </summary>
    [TestFixture]
    public sealed class KeyContainerTests
    {
        private const string Container = @".\DataStore\TestContainer";
        // контейнер с сертификатом внутри
        private const string ContainerSert = @".\DataStore\UnitTestContainer";

        private const string ContainerPassword = "123123";

        /// <summary>
        ///     Подсчет хэша.
        /// </summary>
        [Test]
        public void ComputeHash()
        {
            byte[] data = GetRandomData();

            byte[] hash = Gost2001KeyContainer.ComputeHash(data);

            const int HashLength = 32;
            Assert.AreEqual(HashLength, hash.Length);
        }

        /// <summary>
        ///     Сравнение алгоритма хеширования с Wiki для CriptoPro
        ///     http://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_%D0%A0_34.11-94
        /// </summary>
        [Test]
        public void HashTestFromWiki()
        {
            //GOST("") = 981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0
            byte[] data = Encoding.UTF8.GetBytes("");
            byte[] hash = Gost2001KeyContainer.ComputeHash(data);

            var hexString = HexEncoding.ToString(hash);
            Assert.AreEqual("981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0", hexString);


            //GOST("a") = E74C52DD282183BF37AF0079C9F78055715A103F17E3133CEFF1AACF2F403011
            data = Encoding.UTF8.GetBytes("a");
            hash = Gost2001KeyContainer.ComputeHash(data);

            hexString = HexEncoding.ToString(hash);
            Assert.AreEqual("E74C52DD282183BF37AF0079C9F78055715A103F17E3133CEFF1AACF2F403011", hexString);


            //GOST("abc") = B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C
            data = Encoding.UTF8.GetBytes("abc");
            hash = Gost2001KeyContainer.ComputeHash(data);

            hexString = HexEncoding.ToString(hash);
            Assert.AreEqual("B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C", hexString);


            //GOST("message digest") = BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0
            data = Encoding.UTF8.GetBytes("message digest");
            hash = Gost2001KeyContainer.ComputeHash(data);

            hexString = HexEncoding.ToString(hash);
            Assert.AreEqual("BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0", hexString);
        }

        /// <summary>
        ///     Создание ключевого контейнера.
        /// </summary>
        [Test, Ignore]
        public void CreateKeyContainer()
        {
            const string NewContainer = "Infotecs_FD80A40E-BC07-4D58-BB8E-4B6BE802CC34";
            Gost2001KeyContainer.Create(NewContainer, KeyNumber.Signature);
        }

        /// <summary>
        ///     Проверка экспорта открытого ключа.
        /// </summary>
        [Test]
        public void ExportPublicKey()
        {
            using (InfotecsFacade keyContainer = Gost2001KeyContainer.Open(Container, ContainerPassword))
            {
                byte[] key = keyContainer.ExportPublicKey();
                CollectionAssert.IsNotEmpty(key);
            }
        }

        /// <summary>
        ///     Проверка существования ключевого контейнера.
        /// </summary>
        [Test]
        public void Exist_KeyContainerAbsent_False()
        {
            bool exist = Gost2001KeyContainer.Exist(Guid.NewGuid().ToString());
            Assert.IsFalse(exist);
        }

        /// <summary>
        ///     Проверка существования ключевого контейнера.
        /// </summary>
        [Test]
        public void Exist_KeyContainerExist_True()
        {
            bool exist = Gost2001KeyContainer.Exist(Container);
            Assert.IsTrue(exist);
        }

        /// <summary>
        ///     Проверка подписи хэша.
        /// </summary>
        [Test]
        public void SignHash()
        {
            byte[] data = GetRandomData();

            byte[] signature;
            byte[] hash = Gost2001KeyContainer.ComputeHash(data);

            using (InfotecsFacade keyContainer = Gost2001KeyContainer.Open(Container, ContainerPassword))
            {
                signature = keyContainer.SignHash(hash, KeyNumber.Signature);
            }

            byte[] publicKey = Gost2001KeyContainer.ExportPublicKey(Container);
            bool result = Gost2001KeyContainer.VerifySignature(signature, data, publicKey);

            Assert.IsTrue(result);
        }

        [Test]
        public void ExportCertificate()
        {
            byte[] certificate = Gost2001KeyContainer.ExportCertificateData(ContainerSert);
            CollectionAssert.IsNotEmpty(certificate);
        }

        [Test]
        public void GetCertificatePublicKey()
        {
            using (InfotecsFacade keyContainer = Gost2001KeyContainer.Open(ContainerSert, ContainerPassword))
            {
                var certificateRawData = keyContainer.ExportCertificateData();
                var publicKeyFromCert = Gost2001KeyContainer.GetCertificatePublicKey(certificateRawData);

                var containerKey = keyContainer.ExportPublicKey();

                Assert.AreEqual(containerKey, publicKeyFromCert);
            }
        }

        /// <summary>
        ///     Проверка подписи хэша.
        /// </summary>
        [Test]
        public void SignCertigicateSignature()
        {
            byte[] data = GetRandomData();

            byte[] signature, certificateRawData;
            byte[] hash = Gost2001KeyContainer.ComputeHash(data);


            using (InfotecsFacade keyContainer = Gost2001KeyContainer.Open(ContainerSert, ContainerPassword))
            {
                signature = keyContainer.SignHash(hash, KeyNumber.Signature);
                certificateRawData = keyContainer.ExportCertificateData();
            }

            bool result = Gost2001KeyContainer.VerifyCertificate(signature, data, certificateRawData);
            Assert.IsTrue(result);
        }

        private static byte[] GetRandomData()
        {
            var data = new byte[10];
            new RNGCryptoServiceProvider().GetBytes(data);
            return data;
        }
    }
}
