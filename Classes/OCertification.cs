﻿/*
' /====================================================\
'| Developed Tony N. Hyde (www.k2host.co.uk)            |
'| Projected Started: 2020-03-18                        | 
'| Use: General                                         |
' \====================================================/
*/
using System;
using System.Data;
using System.Collections.Generic;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.X509;

using K2host.Data.Classes;
using K2host.Certificates.Interfaces;
using K2host.Data.Enums;
using System.Data.SqlTypes;

namespace K2host.Certificates.Classes
{

    public class OCertification : ODataObject<OCertification>, ICertification
    {

        /// <summary>
        /// Used to determin this cert as a certification authority
        /// </summary>
        [TSQLDataType(SqlDbType.Bit)]
        public bool IsCertificationAuthority { get; set; }

        /// <summary>
        /// The encryption key size
        /// </summary>
        [TSQLDataType(SqlDbType.Int)]
        public int KeySize { get; set; }

        /// <summary>
        /// The subject name
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 1024)]
        public string SubjectName { get; set; }

        /// <summary>
        /// The friendly name
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 512)]
        public string FriendlyName { get; set; }

        /// <summary>
        /// The name of the algorithm used
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 255)]
        public string Algorithm { get; set; }

        /// <summary>
        /// The expiry date and time.
        /// </summary>
        [TSQLDataType(SqlDbType.DateTime)]
        public DateTime ExpiresIn { get; set; }

        /// <summary>
        /// The list of oid's used on this certificate.
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public List<Oid> Oids { get; set; }

        /// <summary>
        /// The key usage bit mask.
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public KeyUsage KeyUsage { get; set; }

        /// <summary>
        /// The name of the issuser
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 1024)]
        public string IssuerName { get; set; }

        /// <summary>
        /// The issuser private key if any.
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public AsymmetricKeyParameter IssuerPrivateKey { get; set; }

        /// <summary>
        /// Optional: The password thats going to used
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 512)]
        public string Password { get; set; }

        /// <summary>
        /// Optional: The list of alternate domain names
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public List<string> AlternateDomainNames { get; set; }

        /// <summary>
        /// Optional: The list of policies on this certificate
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public Dictionary<Oid, string> Policies { get; set; }

        /// <summary>
        /// Optional: The list of distribution point urls on this certificate.
        /// </summary>
        [TSQLDataException(ODataExceptionType.NON_INSERT | ODataExceptionType.NON_UPDATE | ODataExceptionType.NON_SELECT | ODataExceptionType.NON_DELETE | ODataExceptionType.NON_CREATE)]
        public List<string> DistributionPointUrls { get; set; }

        /// <summary>
        /// Optional: The ocsp url on this certificate.
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 1024)]
        public string OcspUrl { get; set; }

        /// <summary>
        /// Optional: The aia url on this certificate.
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 1024)]
        public string AiaUrl { get; set; }

        /// <summary>
        /// The serial number of the cert after being created.
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 255)]
        public string SerialNumber { get; set; }

        /// <summary>
        /// The revocate state
        /// </summary>
        [TSQLDataType(SqlDbType.Bit)]
        public bool Revocated { get; set; }

        /// <summary>
        /// The date of when it was revocated
        /// </summary>
        [TSQLDataType(SqlDbType.DateTime)]
        public DateTime RevocationDate { get; set; }

        /// <summary>
        /// The pem file that holds the private key.
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 2048)]
        public string PemPrivateKey { get; set; }

        /// <summary>
        /// The pem file that holds the public key.
        /// </summary>
        [TSQLDataType(SqlDbType.NVarChar, 2048)]
        public string PemPublicKey { get; set; }

        /// <summary>
        /// The constructor
        /// </summary>
        public OCertification(string connectionString) : 
            base(connectionString)
        {
            IsCertificationAuthority = false;
            KeySize                 = 0;
            SubjectName             = string.Empty;
            FriendlyName            = string.Empty;
            Algorithm               = string.Empty;
            ExpiresIn               = (DateTime)SqlDateTime.MinValue;
            Oids                    = new List<Oid>();
            KeyUsage                = null;
            IssuerName              = string.Empty;
            IssuerPrivateKey        = null;
            Password                = string.Empty;
            AlternateDomainNames    = new List<string>();
            Policies                = new Dictionary<Oid, string>();
            DistributionPointUrls   = new List<string>();
            OcspUrl                 = string.Empty;
            AiaUrl                  = string.Empty;
            SerialNumber            = string.Empty;
            Revocated               = false;
            RevocationDate          = DateTime.Now;
            PemPrivateKey           = string.Empty;
            PemPublicKey            = string.Empty;
        }

    }

}
