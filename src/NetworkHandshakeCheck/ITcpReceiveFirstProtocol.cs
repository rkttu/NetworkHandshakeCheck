namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Represents a protocol that receives data first from server during a handshake.
    /// </summary>
    public interface ITcpReceiveFirstProtocol : ITcpHandshakeProtocol
    {
        /// <summary>
        /// Gets the expected initial receive data.
        /// </summary>
        /// <remarks>
        /// Used to ensure that the first byte array received from the server starts with the byte array returned by this method.
        /// </remarks>
        /// <returns>
        /// The expected initial receive data.
        /// </returns>
        byte[] GetExpectedInitialReceiveData();
    }
}
