using System;
using System.Security.Cryptography;
using System.Text;
using Infotecs.Cryptography;
using NUnit.Framework;

namespace UnitTests.Cryptography
{
    [TestFixture]
    public sealed class GostKeyContainer2001Tests
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
            const int HashLength = 32;
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    byte[] hash = crypt.ComputeHash(data);
                    Assert.AreEqual(HashLength, hash.Length);
                });
        }

        /// <summary>
        ///     Сравнение алгоритма хеширования с Wiki для CriptoPro
        ///     http://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_%D0%A0_34.11-94
        /// </summary>
        [Test]
        public void HashTestFromWiki()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    //GOST("") = 981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0
                    byte[] data = Encoding.UTF8.GetBytes("");
                    byte[] hash = crypt.ComputeHash(data);

                    var hexString = HexEncoding.ToString(hash);
                    Assert.AreEqual("981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0", hexString);


                    //GOST("a") = E74C52DD282183BF37AF0079C9F78055715A103F17E3133CEFF1AACF2F403011
                    data = Encoding.UTF8.GetBytes("a");
                    hash = crypt.ComputeHash(data);

                    hexString = HexEncoding.ToString(hash);
                    Assert.AreEqual("E74C52DD282183BF37AF0079C9F78055715A103F17E3133CEFF1AACF2F403011", hexString);


                    //GOST("abc") = B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C
                    data = Encoding.UTF8.GetBytes("abc");
                    hash = crypt.ComputeHash(data);

                    hexString = HexEncoding.ToString(hash);
                    Assert.AreEqual("B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C", hexString);


                    //GOST("message digest") = BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0
                    data = Encoding.UTF8.GetBytes("message digest");
                    hash = crypt.ComputeHash(data);

                    hexString = HexEncoding.ToString(hash);
                    Assert.AreEqual("BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0", hexString);
                });
        }

        /// <summary>
        ///     Создание ключевого контейнера.
        /// </summary>
        [Test, Ignore]
        public void CreateKeyContainer()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    const string NewContainer = "Infotecs_FD80A40E-BC07-4D58-BB8E-4B6BE802CC34";
                    crypt.Create(NewContainer, KeyNumber.Signature);
                });
        }

        /// <summary>
        ///     Проверка экспорта открытого ключа.
        /// </summary>
        [Test]
        public void ExportPublicKey()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    using (GostCryptFacade keyContainer = crypt.Open(Container, ContainerPassword))
                    {
                        byte[] key = keyContainer.ExportPublicKey();
                        CollectionAssert.IsNotEmpty(key);
                    }
                });
        }

        /// <summary>
        ///     Проверка существования ключевого контейнера.
        /// </summary>
        [Test]
        public void Exist_KeyContainerAbsent_False()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    bool exist = crypt.Exist(Guid.NewGuid().ToString());
                    Assert.IsFalse(exist);
                });
        }

        /// <summary>
        ///     Проверка существования ключевого контейнера.
        /// </summary>
        [Test]
        public void Exist_KeyContainerExist_True()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    bool exist = crypt.Exist(Container);
                    Assert.IsTrue(exist);
                });
        }

        /// <summary>
        ///     Проверка подписи хэша.
        /// </summary>
        [Test]
        public void SignHash()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    byte[] data = GetRandomData();

                    byte[] signature;
                    byte[] hash = crypt.ComputeHash(data);

                    using (GostCryptFacade keyContainer = crypt.Open(Container, ContainerPassword))
                    {
                        signature = keyContainer.SignHash(hash, KeyNumber.Signature);
                    }

                    byte[] publicKey = crypt.ExportPublicKey(Container);
                    bool result = crypt.VerifySignature(signature, data, publicKey);

                    Assert.IsTrue(result);
                });
        }

        [Test]
        public void ExportCertificate()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    byte[] certificate = crypt.ExportCertificateData(ContainerSert);
                    CollectionAssert.IsNotEmpty(certificate);
                });
        }

        [Test]
        public void GetCertificatePublicKey()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    using (GostCryptFacade keyContainer = crypt.Open(ContainerSert, ContainerPassword))
                    {
                        var certificateRawData = keyContainer.ExportCertificateData();
                        var publicKeyFromCert = crypt.GetCertificatePublicKey(certificateRawData);

                        var containerKey = keyContainer.ExportPublicKey();

                        Assert.AreEqual(containerKey, publicKeyFromCert);
                    }
                });
        }

        /// <summary>
        ///     Проверка подписи хэша.
        /// </summary>
        [Test]
        public void SignCertigicateSignature()
        {
            GostKeyContainer.Get(GostKeyContainer.Signature.Gost34102001,
                crypt =>
                {
                    byte[] data = GetRandomData();

                    byte[] signature, certificateRawData;
                    byte[] hash = crypt.ComputeHash(data);


                    using (GostCryptFacade keyContainer = crypt.Open(ContainerSert, ContainerPassword))
                    {
                        signature = keyContainer.SignHash(hash, KeyNumber.Signature);
                        certificateRawData = keyContainer.ExportCertificateData();
                    }

                    bool result = crypt.VerifyCertificate(signature, data, certificateRawData);
                    Assert.IsTrue(result);
                });
        }

        private static byte[] GetRandomData()
        {
            var data = new byte[10];
            new RNGCryptoServiceProvider().GetBytes(data);
            return data;
        }
    }
}