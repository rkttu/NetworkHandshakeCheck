namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Implements a protocol for SSH handshake testing.
    /// </summary>
    public sealed class SshHandshakeProtocol : ITcpReceiveFirstProtocol
    {
        /// <summary>
        /// Gets the name of the protocol.
        /// </summary>
        public string ProtocolName => "SSH";

        /// <summary>
        /// Gets the default port for the protocol.
        /// </summary>
        public int DefaultPort => 22;

        /// <summary>
        /// Gets a value indicating whether the protocol requires SSL.
        /// </summary>
        public bool RequireSsl => false;

        /// <summary>
        /// Gets the expected initial receive data.
        /// </summary>
        /// <remarks>
        /// Used to ensure that the first byte array received from the server starts with the byte array returned by this method.
        /// </remarks>
        /// <returns>
        /// The expected initial receive data.
        /// </returns>
        public byte[] GetExpectedInitialReceiveData() =>
            new byte[] { 0x53, 0x53, 0x48, 0x2d, };
    }
}
