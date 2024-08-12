namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Implements the Microsoft RDP handshake protocol.
    /// </summary>
    public sealed class RdpHandshakeProtocol : ITcpSendFirstProtocol
    {
        /// <summary>
        /// Gets the name of the protocol.
        /// </summary>
        public string ProtocolName => "MS-RDP";

        /// <summary>
        /// Gets the default port for the protocol.
        /// </summary>
        public int DefaultPort => 3389;

        /// <summary>
        /// Gets a value indicating whether the protocol requires SSL.
        /// </summary>
        public bool RequireSsl => false;

        /// <summary>
        /// Gets the initial send data.
        /// </summary>
        /// <remarks>
        /// Send X.224 Connection Request packet (refer to MS-RDPBCGR document - Client X.224 Connection Request PDU)
        /// </remarks>
        /// <returns>
        /// The initial send data.
        /// </returns>
        public byte[] GetInitialSendData() => new byte[]
        {
            // TPKT Header: TPKT Version
            0x03,

            // TPKT Header: Reserved Byte
            0x00,

            // TPKT Header: Total Packet Length (47-bytes)
            0x00, 0x2f,

            // X.224 Class 0 Data TPDU: X.224 Data TPDU Length (42-bytes)
            0x2a,

            // X.224 Class 0 Data TPDU: X.224 Data TPDU Header (CR-Class 0 TPDU)
            0xe0,

            // RDP Nego Request (X.224 CR-TPDU)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x43,

            // Cookie: mstshash=Microsoft\r\n
            0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x0d, 0x0a,

            // RDP Handshake Options: Packet Type (0x01 means RDP Nego Request)
            0x01,

            // RDP Handshake Options: Padding
            0x00,

            // RDP Handshake Options: Packet Length (This packet has 8-byte length)
            0x08, 0x00,

            // RDP Handshake Options: Flags
            0x00, 0x00, 0x00, 0x00,
        };
    }
}
