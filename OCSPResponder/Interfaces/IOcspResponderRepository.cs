/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OcspResponder.Core
{
    /// <summary>
    /// Contract that an OCSP Responder uses to validate a certificate in a CA repository
    /// </summary>
    public interface IOcspResponderRepository : IDisposable
    {
        /// <summary>
        /// Checks whether the serial exists for this CA repository
        /// </summary>
        /// <param name="serial">serial</param>
        /// <param name="issuerCertificate"></param>
        /// <returns><c>true</c> if the serial exists; otherwise, false</returns>
        bool SerialExists(string serial, X509Certificate2 issuerCertificate);

        /// <summary>
        /// Checks whether the serial is revoked for this CA repository.
        /// </summary>
        /// <param name="serial">serial</param>
        /// <param name="issuerCertificate"></param>
        /// <returns>A <see cref="CertificateRevocationStatus"/> containing whether the certificate is revoked and more info</returns>
        CertificateRevocationStatus SerialIsRevoked(string serial, X509Certificate2 issuerCertificate);

        /// <summary>
        /// Checks whether the CA is compromised.
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns>A <see cref="CaCompromisedStatus"/> containing whether the CA is revoked and when it happens</returns>
        CaCompromisedStatus IsCaCompromised(X509Certificate2 caCertificate);

        /// <summary>
        /// Gets the private key of the CA or its designated responder
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns>A <see cref="AsymmetricAlgorithm"/> that represents the private key of the CA</returns>
        AsymmetricKeyParameter GetResponderPrivateKey(X509Certificate2 caCertificate);

        /// <summary>
        /// Gets the public key of the CA or its designated responder
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns>A <see cref="AsymmetricAlgorithm"/> that represents the private key of the CA</returns>
        AsymmetricKeyParameter GetResponderPublicKey(X509Certificate2 caCertificate);

        /// <summary>
        /// The certificate chain associated with the response signer.
        /// </summary>
        /// <param name="issuerCertificate"></param>
        /// <returns>An array of <see cref="X509Certificate2"/></returns>
        X509Certificate2[] GetChain(X509Certificate2 issuerCertificate);

        /// <summary>
        /// Gets the date when the client should request the responder about the certificate status
        /// </summary>
        /// <returns>A <see cref="DateTime"/> that represents when the client should request the responder again</returns>
        DateTimeOffset GetNextUpdate();

        /// <summary>
        /// Gets the issuer certificate that this repository is responsible to evaluate
        /// </summary>
        /// <returns>A <see cref="X509Certificate2"/> that represents the issuer's certificate</returns>
        IEnumerable<X509Certificate2> GetIssuerCertificates();
    }
}