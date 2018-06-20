using System.Security.Cryptography;
using Infotecs.Cryptography.ProviderParams;

namespace Infotecs.Cryptography
{
    public class Gost2001KeyContainer
    {
        private static readonly GostProviderParams gostProviderParams = ProviderHelper.ParamsForSignAlgoOid("1.2.643.2.2.3"); //new InfotecsProviderParams();

        /// <summary>
        ///     ������� ����.
        /// </summary>
        /// <param name="data">������.</param>
        /// <returns>���.</returns>
        public static byte[] ComputeHash(byte[] data)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.ComputeHash(data);
            }
        }

        /// <summary>
        ///     ������� <see cref="GostCryptFacade" />.
        /// </summary>
        /// <param name="keyContainerName">�������� ��������� ����������.</param>
        /// <param name="keyNumber">��� �����.</param>
        /// <returns>
        ///     ��������� <see cref="GostCryptFacade" />.
        /// </returns>
        public static GostCryptFacade Create(string keyContainerName, KeyNumber keyNumber)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.Create(keyContainerName, keyNumber);
            }
        }

        /// <summary>
        ///     ������� ��������� �����.
        /// </summary>
        /// <param name="keyContainerName">�������� ����������.</param>
        /// <returns>�������� ����.</returns>
        public static byte[] ExportPublicKey(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.ExportPublicKey(keyContainerName);
            }
        }

        /// <summary>
        ///     �������� ���������� ��� ����������� �����
        /// </summary>
        /// <returns></returns>
        public static byte[] ExportCertificateData(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.ExportCertificateData(keyContainerName);
            }
        }

        /// <summary>
        ///     �������� ������� ����������.
        /// </summary>
        /// <param name="keyContainerName">�������� ����������.</param>
        /// <returns>True - ��������� ����������, ����� False.</returns>
        public static bool Exist(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.Exist(keyContainerName);
            }
        }

        /// <summary>
        ///     ������� ������������ ���������.
        /// </summary>
        /// <param name="keyContainerName">�������� ����������.</param>
        /// <param name="keycontainerPassword">������ ��������� ����������.</param>
        /// <returns>
        ///     ��������� <see cref="GostCryptFacade" />.
        /// </returns>
        public static GostCryptFacade Open(string keyContainerName, string keycontainerPassword)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.Open(keyContainerName, keycontainerPassword);
            }
        }

        /// <summary>
        ///     �������� ��������� ����������.
        /// </summary>
        /// <param name="keyContainerName">�������� ����������.</param>
        public static void Remove(string keyContainerName)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                kk.Remove(keyContainerName);
            }
        }

        /// <summary>
        ///     �������� �������.
        /// </summary>
        /// <param name="signature">�������.</param>
        /// <param name="data">������.</param>
        /// <param name="publicKey">�������� ����.</param>
        /// <returns>True - ������� ������ �������, ����� False.</returns>
        public static bool VerifySignature(byte[] signature, byte[] data, byte[] publicKey)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.VerifySignature(signature, data, publicKey);
            }
        }

        /// <summary>
        ///     �������� �������.
        /// </summary>
        /// <param name="signature">�������.</param>
        /// <param name="data">������.</param>
        /// <param name="certificateData">����������.</param>
        /// <returns>True - ������� ������ �������, ����� False.</returns>
        public static bool VerifyCertificate(byte[] signature, byte[] data, byte[] certificateData)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.VerifyCertificate(signature, data, certificateData);
            }
        }

        /// <summary>
        /// ���������� �������� ���� �����������
        /// </summary>
        /// <param name="certificateData">������ �����������</param>
        /// <returns></returns>
        public static byte[] GetCertificatePublicKey(byte[] certificateData)
        {
            var providerParams = gostProviderParams;
            using (var kk = new GostCrypt(providerParams))
            {
                return kk.GetCertificatePublicKey(certificateData);
            }
        }
    }
}