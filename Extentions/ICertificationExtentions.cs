/*
' /====================================================\
'| Developed Tony N. Hyde (www.k2host.co.uk)            |
'| Projected Started: 2020-03-18                        | 
'| Use: General                                         |
' \====================================================/
*/

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1;

using K2host.Certificates.Interfaces;
using Org.BouncyCastle.Pkcs;

namespace K2host.Certificates.Extentions
{

    public static class ICertificationExtentions
    {
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateCertificate(this ICertification e, out AsymmetricKeyParameter privateKey, out AsymmetricKeyParameter publicKey)
        {

            // Generators
            CryptoApiRandomGenerator    RanGen      = new();
            SecureRandom                SecRan      = new(RanGen);
            X509V3CertificateGenerator  PreCert     = new();
            RsaKeyPairGenerator         KeyPairGen  = new();

            KeyPairGen.Init(
                new KeyGenerationParameters(
                    SecRan,
                    e.KeySize
                )
            );

            // Create Subject Public Key
            AsymmetricCipherKeyPair SubjectKeyPair = KeyPairGen.GenerateKeyPair();

            // For Generating the Certificate
            ISignatureFactory SigFactory = new Asn1SignatureFactory(
                e.Algorithm,
                e.IssuerPrivateKey ?? SubjectKeyPair.Private,
                SecRan
            );

            // Set The Serial Number
            PreCert.SetSerialNumber(
                BigIntegers.CreateRandomInRange(
                    BigInteger.One,
                    BigInteger.ValueOf(
                        long.MaxValue
                    ),
                    SecRan
                )
            );

            // Issuer and Subject Name
            X509Name SubjectName = new(
                e.SubjectName
            );

            X509Name IssuerName = new(
                string.IsNullOrEmpty(e.IssuerName) ? e.SubjectName : e.IssuerName
            );

            //Lets set the issuser name to the subject name if this a ca cert top tire.
            if(string.IsNullOrEmpty(e.IssuerName) && e.IsCertificationAuthority)
                e.IssuerName = e.SubjectName;

            PreCert.SetSubjectDN(SubjectName);
            PreCert.SetIssuerDN(IssuerName);

            // Valid For
            PreCert.SetNotBefore(
                DateTime.UtcNow.Date
            );

            PreCert.SetNotAfter(
                e.ExpiresIn.ToUniversalTime().Date
            );

            // Extensions
            PreCert.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(e.IsCertificationAuthority)
            );

            PreCert.AddExtension(
                X509Extensions.KeyUsage,
                true,
                e.KeyUsage
            );

            // DNS Alternative Names
            if (e.AlternateDomainNames.Count > 0)
                PreCert.AddExtension(
                    X509Extensions.SubjectAlternativeName,
                    false,
                    GeneralNames.GetInstance(
                        new DerSequence(
                            e.AlternateDomainNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray()
                        )
                    )
                );

            // Extended Key Usage
            if (e.Oids.Count > 0)
                PreCert.AddExtension(
                    X509Extensions.ExtendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(
                        e.Oids.Select(n => new DerObjectIdentifier(n.Value)).ToArray()
                    )
                );

            // AIA Extension
            if (!string.IsNullOrEmpty(e.OcspUrl) || !string.IsNullOrEmpty(e.AiaUrl))
            {
                SysadminsLV.Asn1Parser.Asn1Builder b = new();
                if (!string.IsNullOrEmpty(e.OcspUrl))
                    b.AddSequence(x => x.AddObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.1"))
                        .AddImplicit(6, Encoding.ASCII.GetBytes(e.OcspUrl), true));
                if (!string.IsNullOrEmpty(e.AiaUrl))
                    b.AddSequence(x => x.AddObjectIdentifier(new Oid("1.3.6.1.5.5.7.48.2"))
                        .AddImplicit(6, Encoding.ASCII.GetBytes(e.AiaUrl), true));
                PreCert.AddExtension(X509Extensions.AuthorityInfoAccess, false, Asn1OctetString.FromByteArray(b.GetEncoded()));
            }

            // Certificate Policies Extension
            if (e.Policies.Count > 0)
            {
                PolicyInformation[] pifo = e.Policies.Select(n => new PolicyInformation(
                    new DerObjectIdentifier(n.Key.Value),
                    new DerSequence(new PolicyQualifierInfo(n.Value)
                ))).ToArray();
                PreCert.AddExtension(X509Extensions.CertificatePolicies, false, new CertificatePolicies(pifo));
            }

            // Extension Distribution Point Crl
            if (e.DistributionPointUrls.Count > 0)
            {
                DistributionPoint[] cdps = e.DistributionPointUrls.Select(n => new DistributionPoint(
                    new DistributionPointName(
                        DistributionPointName.FullName,
                        new GeneralName(GeneralName.UniformResourceIdentifier, n)
                    ), null, null)).ToArray();
                PreCert.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(cdps));
            }

            PreCert.SetPublicKey(SubjectKeyPair.Public);

            Org.BouncyCastle.X509.X509Certificate X509Cert = PreCert.Generate(SigFactory);

            X509Certificate2 X509RealCert2 = null;

            privateKey  = SubjectKeyPair.Private;
            publicKey   = SubjectKeyPair.Public;

            if (e.IsCertificationAuthority)
                X509RealCert2 = new X509Certificate2(X509Cert.GetEncoded())
                {
                    FriendlyName = e.FriendlyName
                };
            else
            {

                Pkcs12Store             store              = new();
                X509CertificateEntry    certificateEntry    = new(X509Cert);

                store.SetCertificateEntry(e.FriendlyName, certificateEntry);
                store.SetKeyEntry(e.FriendlyName, new AsymmetricKeyEntry(SubjectKeyPair.Private), new[] { certificateEntry });

                MemoryStream ms = new();
                store.Save(ms, e.Password.ToCharArray(), SecRan);

                //File.WriteAllBytes("foo.pfx", stream.ToArray());

                X509RealCert2 = new X509Certificate2(ms.ToArray(), e.Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable)
                {
                    FriendlyName = e.FriendlyName
                };

                //    RsaPrivateCrtKeyParameters pk = (RsaPrivateCrtKeyParameters)SubjectKeyPair.Private;

                //    X509RealCert2 = X509RealCert2.CopyWithPrivateKey(
                //        RSA.Create(
                //            new RSAParameters()
                //            {
                //                Modulus = pk.Modulus.ToByteArrayUnsigned(),
                //                P = pk.P.ToByteArrayUnsigned(),
                //                Q = pk.Q.ToByteArrayUnsigned(),
                //                DP = pk.DP.ToByteArrayUnsigned(),
                //                DQ = pk.DQ.ToByteArrayUnsigned(),
                //                InverseQ = pk.QInv.ToByteArrayUnsigned(),
                //                D = pk.Exponent.ToByteArrayUnsigned(),
                //                Exponent = pk.PublicExponent.ToByteArrayUnsigned()
                //            }));

                ms.Close();
                ms.Dispose();

            }

            e.PemPublicKey  = publicKey.WritePemString();
            e.PemPrivateKey = privateKey.WritePemString();
            e.SerialNumber  = X509RealCert2.SerialNumber;

            return X509RealCert2;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="_"></param>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter ReadPemFile(this ICertification _, string filePath)
        {
            AsymmetricCipherKeyPair keyPair;

            using (StreamReader reader = File.OpenText(filePath))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            }

            return keyPair.Private;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter ReadPemPrivateKey(this ICertification e)
        {
            AsymmetricKeyParameter kp;

            using MemoryStream ms = new(Encoding.UTF8.GetBytes(e.PemPrivateKey));
            using StreamReader rr = new(ms);
            kp = ((AsymmetricCipherKeyPair)new PemReader(rr).ReadObject()).Private;

            return kp;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter ReadPemPublicKey(this ICertification e)
        {
            AsymmetricKeyParameter kp;

            using MemoryStream ms = new(Encoding.UTF8.GetBytes(e.PemPublicKey));
            using StreamReader rr = new(ms);
            kp = ((AsymmetricCipherKeyPair)new PemReader(rr).ReadObject()).Public;

            return kp;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e">The private key</param>
        /// <param name="filePath">full file path</param>
        public static void WritePemFile(this AsymmetricKeyParameter e, string filePath)
        {
            try
            {
                TextWriter tw = new StringWriter();

                PemWriter pemCreator = new(tw);
                pemCreator.WriteObject((RsaKeyParameters)e);
                pemCreator.Writer.Flush();

                File.WriteAllText(filePath, tw.ToString());
            }
            catch (Exception)
            {
                throw;
            }

        }
       
        /// <summary>
        /// 
        /// </summary>
        /// <param name="e">The private key</param>
        /// <param name="filePath">full file path</param>
        public static string WritePemString(this AsymmetricKeyParameter e)
        {
            try
            {
                TextWriter tw = new StringWriter();

                PemWriter pemCreator = new(tw);
                pemCreator.WriteObject((RsaKeyParameters)e);
                pemCreator.Writer.Flush();

                return tw.ToString();
            }
            catch (Exception)
            {
                throw;
            }

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        /// <param name="storeName"></param>
        /// <param name="storeLocation"></param>
        /// <returns></returns>
        public static X509Certificate2 Install(this X509Certificate2 e, StoreName storeName, StoreLocation storeLocation)
        {

            try
            {
              
                X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Add(e);
                store.Close();
                return e;
           
            }
            catch(Exception)
            {
                return e;
            }

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public static List<string> GetAlternativeSubjectNames(this X509Certificate2 cert)
        {
            List<string> result = new();

            string subjectAlternativeName = cert.Extensions.Cast<System.Security.Cryptography.X509Certificates.X509Extension>()
                                                .Where(n => n.Oid.Value == "2.5.29.17")
                                                .Select(n => new AsnEncodedData(n.Oid, n.RawData))
                                                .Select(n => n.Format(true))
                                                .FirstOrDefault();

            if (subjectAlternativeName != null)
            {
               
                string[] alternativeNames = subjectAlternativeName.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
               
                foreach (string alternativeName in alternativeNames)
                {

                    GroupCollection groups = Regex.Match(alternativeName, @"^(.*)=(.*)").Groups; // @"^DNS Name=(.*)").Groups;
                    if (groups.Count > 0 && !string.IsNullOrEmpty(groups[2].Value))
                        result.Add(groups[2].Value);

                }

            }

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public static Org.BouncyCastle.X509.X509Certificate ToBouncyCert(this X509Certificate2 cert)
        {
            return new X509CertificateParser().ReadCertificate(cert.GetRawCertData());
        }



    }


}