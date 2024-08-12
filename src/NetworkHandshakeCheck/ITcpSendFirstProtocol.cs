namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Represents a protocol that sends data first to server during a handshake.
    /// </summary>
    public interface ITcpSendFirstProtocol : ITcpHandshakeProtocol
    {
        /// <summary>
        /// Gets the initial send data.
        /// </summary>
        /// <returns>
        /// The initial send data.
        /// </returns>
        byte[] GetInitialSendData();
    }
}
