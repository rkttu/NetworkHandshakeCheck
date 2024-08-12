namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Represents a protocol properties for handshake testing.
    /// </summary>
    public interface ITcpHandshakeProtocol
    {
        /// <summary>
        /// Gets the name of the protocol.
        /// </summary>
        string ProtocolName { get; }

        /// <summary>
        /// Gets the default port for the protocol.
        /// </summary>
        int DefaultPort { get; }

        /// <summary>
        /// Gets a value indicating whether the protocol requires SSL.
        /// </summary>
        bool RequireSsl { get; }
    }
}
