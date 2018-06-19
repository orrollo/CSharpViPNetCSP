using System.Security.Cryptography;
using Infotecs.Cryptography.ProviderParams;

namespace Infotecs.Cryptography
{
    public class Gost2001KeyContainer
    {
        static readonly GostProviderParams gostProviderParams = new InfotecsProviderParams();

        /// <summary>
        ///     Подсчет хэша.
        /// </summary>
        /// <param name="data">Данные.</param>
        /// <returns>Хэш.</returns>
        public static byte[] ComputeHash(byte[] data)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.ComputeHash(data);
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
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.Create(keyContainerName, keyNumber);
            }
        }

        /// <summary>
        ///     Экспорт открытого ключа.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>Открытый ключ.</returns>
        public static byte[] ExportPublicKey(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.ExportPublicKey(keyContainerName);
            }
        }

        /// <summary>
        ///     Получить сертификат для конкретного ключа
        /// </summary>
        /// <returns></returns>
        public static byte[] ExportCertificateData(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.ExportCertificateData(keyContainerName);
            }
        }

        /// <summary>
        ///     Провекра наличия контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        /// <returns>True - контейнер существует, иначе False.</returns>
        public static bool Exist(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.Exist(keyContainerName);
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
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.Open(keyContainerName, keycontainerPassword);
            }
        }

        /// <summary>
        ///     Удаление ключевого контейнера.
        /// </summary>
        /// <param name="keyContainerName">Название контейнера.</param>
        public static void Remove(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                kk.Remove(keyContainerName);
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
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.VerifySignature(signature, data, publicKey);
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
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.VerifyCertificate(signature, data, certificateData);
            }
        }

        /// <summary>
        /// Возвращает открытый ключ сертификата
        /// </summary>
        /// <param name="certificateData">данные сертификата</param>
        /// <returns></returns>
        public static byte[] GetCertificatePublicKey(byte[] certificateData)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostInfotecs(providerParams))
            {
                return kk.GetCertificatePublicKey(certificateData);
            }
        }
    }
}