using System;
using System.Linq;
using System.Numerics;
using SysadminsLV.Asn1Parser.Utils.CLRExtensions;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents an ASN.1 <strong>INTEGER</strong> data type.
    /// </summary>
    public sealed class Asn1Integer : UniversalTagBase {
        const Asn1Type TYPE = Asn1Type.INTEGER;
        const Byte     TAG  = (Byte)TYPE;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1Integer</strong> class from an <see cref="Asn1Reader"/>
        /// object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not valid <strong>INTEGER</strong> data type.
        /// </exception>
        public Asn1Integer(Asn1Reader asn) : base(asn) {
            if (asn.Tag != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            m_decode(asn);
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1Integer</strong> from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// <strong>rawData</strong> is not valid <strong>INTEGER</strong> data type.
        /// </exception>
        public Asn1Integer(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1Integer</strong> class from an integer value.
        /// </summary>
        /// <param name="inputInteger">Integer value to encode.</param>
        public Asn1Integer(BigInteger inputInteger) {
            m_encode(inputInteger);
        }

        /// <summary>
        /// Gets value associated with the current object.
        /// </summary>
        public BigInteger Value { get; private set; }

        void m_encode(BigInteger inputInteger) {
            Value = inputInteger;
            Initialize(new Asn1Reader(Asn1Utils.Encode(inputInteger.GetAsnBytes(), TAG)));
        }
        void m_decode(Asn1Reader asn) {
            Value = new BigInteger(asn.GetPayload().Reverse().ToArray());
        }
    }
}
