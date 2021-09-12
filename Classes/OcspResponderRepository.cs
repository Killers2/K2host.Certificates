/*
' /====================================================\
'| Developed Tony N. Hyde (www.k2host.co.uk)            |
'| Projected Started: 2020-03-18                        | 
'| Use: General                                         |
' \====================================================/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using OcspResponder.Core;

using Org.BouncyCastle.Crypto;

using K2host.Core;
using K2host.Data.Classes;
using K2host.Certificates.Extentions;

namespace K2host.Certificates.Classes
{

    public class OcspResponderRepository : IOcspResponderRepository
    {
        
        /// <summary>
        /// 
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Return all the certs up the chain based on the issuer certificate 
        /// </summary>
        /// <param name="issuerCertificate"></param>
        /// <returns></returns>
        public X509Certificate2[] GetChain(X509Certificate2 issuerCertificate)
        {

            List<X509Certificate2> output = new();

            X509Chain ch = new();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.Build(issuerCertificate);
            ch.ChainElements.OfType<X509ChainElement>().ForEach(l => { output.Add(l.Certificate); });

            output.Reverse();

            return output.ToArray();

        }

        /// <summary>
        /// Returns all certs that were issued by this CA on this domain.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<X509Certificate2> GetIssuerCertificates()
        {

            List<X509Certificate2> output = new();

            OCertification[] dbCerts = OCertification.List(0,
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("IsCertificationAuthority"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { false }
                    }
                },
                null,
                null,
                ConnectionString,
                out ODataException dex
            ).ToArray();

            if (dex != null)
                throw dex;

            var store = new X509Store(StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            dbCerts.ForEach(c => {
              
                output.AddRange(store.Certificates.Find(X509FindType.FindBySerialNumber, c.SerialNumber, true).OfType<X509Certificate2>());
           
            });

            store.Close();

            return output.ToArray();

        }
       
        /// <summary>
        /// Make the client request an update in 7 days
        /// </summary>
        /// <returns></returns>
        public DateTimeOffset GetNextUpdate()
        {
            return DateTimeOffset.UtcNow.AddDays(7);
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns></returns>
        public AsymmetricKeyParameter GetResponderPrivateKey(X509Certificate2 caCertificate)
        {

            //get the cert from the database and returen the private key
            var dbCert = OCertification.Retrieve(
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("SerialNumber"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { caCertificate.SerialNumber.ToUpper() }
                    }
                },
                null,
                null,
                ConnectionString,
                out ODataException dex
            );

            if (dex != null)
                throw dex;

            return dbCert.ReadPemPrivateKey();

        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns></returns>
        public AsymmetricKeyParameter GetResponderPublicKey(X509Certificate2 caCertificate)
        {

            //get the cert from the database and returen the private key
            var dbCert = OCertification.Retrieve(
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("SerialNumber"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { caCertificate.SerialNumber.ToUpper() }
                    }
                },
                null,
                null,
                ConnectionString,
                out ODataException dex
            );

            if (dex != null)
                throw dex;

            return dbCert.ReadPemPublicKey();

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="caCertificate"></param>
        /// <returns></returns>
        public CaCompromisedStatus IsCaCompromised(X509Certificate2 caCertificate)
        {
            
            var dbCert = OCertification.Retrieve(
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("SerialNumber"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { caCertificate.SerialNumber.ToUpper() }
                    }
                },
                null,
                null,
                ConnectionString,
                out ODataException dex
            );

            if (dex != null)
                throw dex;

            var state = new CaCompromisedStatus()
            {
                CompromisedDate = DateTimeOffset.MinValue,
                IsCompromised   = false
            };

            if (dbCert.Revocated || dbCert.ExpiresIn <= DateTime.Now)
            {
                state.IsCompromised = true;
                if (dbCert.Revocated)
                    state.CompromisedDate = dbCert.RevocationDate;
                if (dbCert.ExpiresIn <= DateTime.Now)
                    state.CompromisedDate = dbCert.ExpiresIn;
            }

            return state;

        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="serial"></param>
        /// <param name="issuerCertificate"></param>
        /// <returns></returns>
        public bool SerialExists(string serial, X509Certificate2 issuerCertificate)
        {

            var dbCert = OCertification.Retrieve(
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("SerialNumber"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { serial.ToUpper() }
                    }
                },
                null,
                null,
                ConnectionString,
                out _
            );

            return issuerCertificate.SerialNumber.ToUpper().Equals(serial.ToUpper()) && dbCert != null;

        }
       
        /// <summary>
        /// 
        /// </summary>
        /// <param name="serial"></param>
        /// <param name="issuerCertificate"></param>
        /// <returns></returns>
        public CertificateRevocationStatus SerialIsRevoked(string serial, X509Certificate2 issuerCertificate)
        {

            var output = new CertificateRevocationStatus()
            {
                IsRevoked   = false,
                RevokedInfo = new RevokedInfo()
                {
                    Date    = DateTimeOffset.MinValue,
                    Reason  = RevocationReason.Unspecified
                }
            };

            var dbCert = OCertification.Retrieve(
                new ODataCondition[] {
                    new ODataCondition() {
                        Column      = typeof(OCertification).GetProperty("SerialNumber"),
                        Operator    = Data.Enums.ODataOperator.EQUAL,
                        Values      = new object[] { serial.ToUpper() }
                    }
                },
                null,
                null,
                ConnectionString,
                out _
            );

            if (issuerCertificate.SerialNumber.ToUpper().Equals(serial.ToUpper()) && dbCert != null)
                if (dbCert.Revocated)
                {
                    output.IsRevoked = true;
                    output.RevokedInfo.Date = dbCert.RevocationDate;
                }

            if (dbCert == null)
                if (dbCert.Revocated)
                {
                    output.IsRevoked        = true;
                    output.RevokedInfo.Date = DateTime.Now;
                }

            return output;

        }
      
        #region Deconstuctor

        private bool IsDisposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
                if (disposing)
                {


                }
            IsDisposed = true;
        }

        #endregion

    }
}
