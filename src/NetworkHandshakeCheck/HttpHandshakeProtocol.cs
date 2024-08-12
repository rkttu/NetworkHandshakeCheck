namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Implements a protocol for HTTP handshake testing.
    /// </summary>
    public sealed class HttpHandshakeProtocol : ITcpSendFirstProtocol
    {
        /// <summary>
        /// Gets the name of the protocol.
        /// </summary>
        public string ProtocolName => "HTTP";

        /// <summary>
        /// Gets the default port for the protocol.
        /// </summary>
        public int DefaultPort => 80;

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
        public byte[] GetInitialSendData() =>
            new byte[] { 0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A, 0x0D, 0x0A, };
    }
}
