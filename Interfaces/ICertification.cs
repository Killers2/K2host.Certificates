/*
' /====================================================\
'| Developed Tony N. Hyde (www.k2host.co.uk)            |
'| Projected Started: 2020-03-18                        | 
'| Use: General                                         |
' \====================================================/
*/
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.X509;

using K2host.Data.Interfaces;

namespace K2host.Certificates.Interfaces
{

    public interface ICertification : IDataObject
    {

        /// <summary>
        /// Used to determin this cert as a certification authority
        /// </summary>
        bool IsCertificationAuthority { get; set; }

        /// <summary>
        /// The encryption key size
        /// </summary>
        int KeySize { get; set; }

        /// <summary>
        /// The subject name
        /// </summary>
        string SubjectName { get; set; }

        /// <summary>
        /// The friendly name
        /// </summary>
        string FriendlyName { get; set; }

        /// <summary>
        /// The name of the algorithm used
        /// </summary>
        string Algorithm { get; set; }

        /// <summary>
        /// The expiry date and time.
        /// </summary>
        DateTime ExpiresIn { get; set; }

        /// <summary>
        /// The list of oid's used on this certificate.
        /// </summary>
        List<Oid> Oids { get; set; }

        /// <summary>
        /// The key usage bit mask.
        /// </summary>
        KeyUsage KeyUsage { get; set; }

        /// <summary>
        /// The name of the issuser
        /// </summary>
        string IssuerName { get; set; }

        /// <summary>
        /// The issuser private key if any.
        /// </summary>
        AsymmetricKeyParameter IssuerPrivateKey { get; set; }

        /// <summary>
        /// Optional: The password thats going to used
        /// </summary>
        string Password { get; set; }

        /// <summary>
        /// Optional: The list of alternate domain names
        /// </summary>
        List<string> AlternateDomainNames { get; set; }

        /// <summary>
        /// Optional: The list of policies on this certificate
        /// </summary>
        Dictionary<Oid, string> Policies { get; set; }

        /// <summary>
        /// Optional: The list of distribution point urls on this certificate.
        /// </summary>
        List<string> DistributionPointUrls { get; set; }

        /// <summary>
        /// Optional: The ocsp url on this certificate.
        /// </summary>
        string OcspUrl { get; set; }

        /// <summary>
        /// Optional: The aia url on this certificate.
        /// </summary>
        string AiaUrl { get; set; }

        /// <summary>
        /// The serial number of the cert after being created.
        /// </summary>
        string SerialNumber { get; set; }

        /// <summary>
        /// The revocate state
        /// </summary>
        bool Revocated { get; set; }

        /// <summary>
        /// The date of when it was revocated
        /// </summary>
        DateTime RevocationDate { get; set; }

        /// <summary>
        /// The pem file that holds the private key.
        /// </summary>
        string PemPrivateKey { get; set; }

        /// <summary>
        /// The pem file that holds the public key.
        /// </summary>
        string PemPublicKey { get; set; }


    }

}