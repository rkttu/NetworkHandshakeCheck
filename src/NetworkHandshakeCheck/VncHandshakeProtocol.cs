namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Implements a VNC handshake protocol.
    /// </summary>
    public sealed class VncHandshakeProtocol : ITcpSendFirstProtocol
    {
        /// <summary>
        /// Gets the name of the protocol.
        /// </summary>
        public string ProtocolName => "VNC";

        /// <summary>
        /// Gets the default port for the protocol.
        /// </summary>
        public int DefaultPort => 5900;

        /// <summary>
        /// Gets a value indicating whether the protocol requires SSL.
        /// </summary>
        public bool RequireSsl => false;

        /// <summary>
        /// Gets the initial send data.
        /// </summary>
        /// <returns>
        /// The initial send data.
        /// </returns>
        public byte[] GetInitialSendData() => new byte[]
        {
            // RFB
            0x52, 0x46, 0x42,

            // [ ]
            0x20,

            // 003
            0x30, 0x30, 0x33,

            // .
            0x2E,

            // 008
            0x30, 0x30, 0x38,

            // \n
            0x0A,
        };
    }
}
