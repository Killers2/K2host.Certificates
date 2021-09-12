/*
' /====================================================\
'| Developed Gabriel Calegari                           |
'| URL: https://github.com/gabrielcalegari              | 
'| Use: General                                         |
' \====================================================/
*/
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace OcspResponder.Core.Internal
{
    /// <summary>
    /// Extensions for OcspObjectIdentifiers
    /// </summary>
    internal class OcspObjectIdentifierExtensions : OcspObjectIdentifiers
    {
        public static readonly DerObjectIdentifier PkixOscpPrefSigAlgs = new(PkixOcsp + ".8");

        public static readonly DerObjectIdentifier PkixOcspExtendedRevoke = new(PkixOcsp + ".9");
    }
}