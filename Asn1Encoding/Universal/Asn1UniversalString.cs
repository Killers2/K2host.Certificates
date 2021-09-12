﻿using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents an ASN.1 <strong>UniversalString</strong> data type. Universal String represents strings where each character
    /// is encoded using 4 bytes.
    /// </summary>
    public sealed class Asn1UniversalString : Asn1String {
        const Asn1Type TYPE = Asn1Type.UniversalString;
        const Byte     TAG  = (Byte)TYPE;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UniversalString</strong> class from an <see cref="Asn1Reader"/>
        /// object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not <strong>UniversalString</strong> data type.
        /// </exception>
        public Asn1UniversalString(Asn1Reader asn) : base(asn) {
            if (asn.Tag != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            m_decode(asn);
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1UniversalString</strong> from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// <strong>rawData</strong> is not <strong>UniversalString</strong> data type.
        /// </exception>
        public Asn1UniversalString(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UniversalString</strong> class from a unicode string.
        /// </summary>
        /// <param name="inputString">A unicode string to encode.</param>
        /// <exception cref="InvalidDataException">
        /// <strong>inputString</strong> contains invalid PrintableString characters
        /// </exception>
        public Asn1UniversalString(String inputString) {
            m_encode(inputString);
        }

        void m_encode(String inputString) {
            Value = inputString;
            Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.UTF32.GetBytes(inputString.Reverse().ToArray()).Reverse().ToArray(), TAG)));
        }
        void m_decode(Asn1Reader asn) {
            Value = new String(Encoding.UTF32.GetString(asn.GetPayload().Reverse().ToArray()).Reverse().ToArray());
        }

        /// <inheritdoc/>
        public override String GetDisplayValue() {
            return Value;
        }
    }
}
