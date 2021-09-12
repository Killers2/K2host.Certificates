/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace OcspResponder.Core.Internal
{
    /// <inheritdoc />
    internal class BcOcspResponderRepositoryAdapter : IBcOcspResponderRepository
    {
        /// <inheritdoc />
        public bool SerialExists(BigInteger serial, X509Certificate issuerCertificate)
        {
            var dotNetCertificate = new X509Certificate2(issuerCertificate.GetEncoded());
            return OcspResponderRepository.SerialExists(serial.ToString(), dotNetCertificate);
        }

        /// <inheritdoc />
        public CertificateRevocationStatus SerialIsRevoked(BigInteger serial, X509Certificate issuerCertificate)
        {
            var dotNetCertificate = new X509Certificate2(issuerCertificate.GetEncoded());
            return OcspResponderRepository.SerialIsRevoked(serial.ToString(), dotNetCertificate);
        }

        /// <param name="caCertificate"></param>
        /// <inheritdoc />
        public CaCompromisedStatus IsCaCompromised(X509Certificate caCertificate)
        {
            var dotNetCertificate = new X509Certificate2(caCertificate.GetEncoded());
            return OcspResponderRepository.IsCaCompromised(dotNetCertificate);
        }

        /// <param name="caCertificate"></param>
        /// <inheritdoc />
        public AsymmetricKeyParameter GetResponderPrivateKey(X509Certificate caCertificate)
        {
            //var dotNetCertificate = new X509Certificate2(caCertificate.GetEncoded());
            //var privateKey = OcspResponderRepository.GetResponderPrivateKey(dotNetCertificate);
            //return DotNetUtilities.GetKeyPair(privateKey).Private;
            return OcspResponderRepository.GetResponderPrivateKey(new X509Certificate2(caCertificate.GetEncoded()));
        }

        /// <inheritdoc />
        public AsymmetricKeyParameter GetResponderPublicKey(X509Certificate caCertificate)
        {
            //var dotNetCertificate = new X509Certificate2(caCertificate.GetEncoded());
            //var privateKey = OcspResponderRepository.GetResponderPrivateKey(dotNetCertificate);
            //return DotNetUtilities.GetKeyPair(privateKey).Public;
            return OcspResponderRepository.GetResponderPublicKey(new X509Certificate2(caCertificate.GetEncoded()));
        }

        /// <param name="issuerCertificate"></param>
        /// <inheritdoc />
        public X509Certificate[] GetChain(X509Certificate issuerCertificate)
        {
            var dotNetCertificate = new X509Certificate2(issuerCertificate.GetEncoded());
            var certificates = OcspResponderRepository.GetChain(dotNetCertificate);
            return certificates.Select(DotNetUtilities.FromX509Certificate).ToArray();
        }

        /// <inheritdoc />
        public IEnumerable<X509Certificate> GetIssuerCertificates()
        {
            var certificates = OcspResponderRepository.GetIssuerCertificates();
            return certificates.Select(DotNetUtilities.FromX509Certificate).ToArray();
        }

        /// <inheritdoc />
        public DateTimeOffset GetNextUpdate()
        {
            return OcspResponderRepository.GetNextUpdate();
        }

        /// <see cref="OcspResponderRepository"/>
        private IOcspResponderRepository OcspResponderRepository { get; }

        internal BcOcspResponderRepositoryAdapter(IOcspResponderRepository ocspResponderRepository)
        {
            OcspResponderRepository = ocspResponderRepository;
        }
    }
}