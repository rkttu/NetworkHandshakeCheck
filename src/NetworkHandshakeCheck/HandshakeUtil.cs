using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkHandshakeCheck
{
    /// <summary>
    /// Provides utility methods for handshake testing.
    /// </summary>
    public static class HandshakeUtil
    {
        /// <summary>
        /// Queries IP addresses of the specified host name.
        /// </summary>
        /// <param name="hostName">
        /// The host name to query IP addresses.
        /// </param>
        /// <param name="timeout">
        /// The timeout for the query operation.
        /// </param>
        /// <param name="cancellationToken">
        /// The cancellation token to cancel the operation.
        /// </param>
        /// <returns>
        /// The IP addresses of the specified host name.
        /// </returns>
        /// <exception cref="TimeoutException">
        /// The query operation is timed out.
        /// </exception>
        public static async Task<IEnumerable<IPAddress>> QueryIPAddressesAsync(
            string hostName, TimeSpan? timeout = default, CancellationToken cancellationToken = default)
        {
            var dnsQueryTask = Dns.GetHostAddressesAsync(hostName);
            var timeoutTask = Task.Delay(timeout.HasValue ? timeout.Value : Timeout.InfiniteTimeSpan, cancellationToken);
            var resultTask = await Task.WhenAny(dnsQueryTask, timeoutTask).ConfigureAwait(false);

            if (!object.ReferenceEquals(resultTask, dnsQueryTask))
                throw new TimeoutException("DNS query timeout");

            return await dnsQueryTask.ConfigureAwait(false);
        }

        /// <summary>
        /// Tests the TCP handshake with the specified protocol.
        /// </summary>
        /// <typeparam name="THandshakeProtocol">
        /// The type of the handshake protocol.
        /// </typeparam>
        /// <param name="protocol">
        /// The protocol to test the TCP handshake.
        /// </param>
        /// <param name="hostName">
        /// The host name to test the TCP handshake.
        /// </param>
        /// <param name="port">
        /// The port to test the TCP handshake.
        /// </param>
        /// <param name="timeout">
        /// The timeout for the TCP handshake operation.
        /// </param>
        /// <param name="exceptionHandler">
        /// The exception handler to handle exceptions during the operation.
        /// </param>
        /// <param name="remoteCertificateValidationCallback">
        /// The callback to validate the server certificate.
        /// </param>
        /// <param name="cancellationToken">
        /// The cancellation token to cancel the operation.
        /// </param>
        /// <returns>
        /// The IP address of the host name if the TCP handshake is successful; otherwise, <see langword="null"/>.
        /// </returns>
        public static async Task<IPAddress?> TestTcpHandshakeAsync<THandshakeProtocol>(
            this THandshakeProtocol protocol, string hostName,
            int? port = default, TimeSpan? timeout = default, Action<Exception>? exceptionHandler = default,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback = default,
            CancellationToken cancellationToken = default)
            where THandshakeProtocol : ITcpHandshakeProtocol
        {
            var ipAddresses = await QueryIPAddressesAsync(hostName, timeout, cancellationToken).ConfigureAwait(false);
            foreach (var ipAddress in ipAddresses)
            {
                var result = await protocol
                    .TestTcpHandshakeAsync(ipAddress, port, timeout, exceptionHandler, remoteCertificateValidationCallback, cancellationToken)
                    .ConfigureAwait(false);
                if (result) return ipAddress;
            }
            return null;
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        { return true; }

        /// <summary>
        /// Tests the TCP handshake with the specified protocol.
        /// </summary>
        /// <typeparam name="TTcpHandshakeProtocol">
        /// The type of the handshake protocol.
        /// </typeparam>
        /// <param name="protocol">
        /// The protocol to test the TCP handshake.
        /// </param>
        /// <param name="ipAddress">
        /// The IP address to test the TCP handshake.
        /// </param>
        /// <param name="port">
        /// The port to test the TCP handshake.
        /// </param>
        /// <param name="timeout">
        /// The timeout for the TCP handshake operation.
        /// </param>
        /// <param name="exceptionHandler">
        /// The exception handler to handle exceptions during the operation.
        /// </param>
        /// <param name="remoteCertificateValidationCallback">
        /// The callback to validate the server certificate.
        /// </param>
        /// <param name="cancellationToken">
        /// The cancellation token to cancel the operation.
        /// </param>
        /// <returns>
        /// The IP address of the host name if the TCP handshake is successful; otherwise, <see langword="null"/>.
        /// </returns>
        public static async Task<bool> TestTcpHandshakeAsync<TTcpHandshakeProtocol>(
            this TTcpHandshakeProtocol protocol, IPAddress ipAddress,
            int? port = default, TimeSpan? timeout = default, Action<Exception>? exceptionHandler = default,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback = default,
            CancellationToken cancellationToken = default)
            where TTcpHandshakeProtocol : ITcpHandshakeProtocol
        {
            if (protocol == null)
                throw new ArgumentNullException(nameof(protocol));

            if (!timeout.HasValue || timeout.Value.Ticks < 0L)
                timeout = TimeSpan.FromSeconds(5d);

            port = port ?? protocol.DefaultPort;

            var buffer = new byte[64000];
            var ipEndPoint = new IPEndPoint(ipAddress, port.Value);

            using (var timeoutCancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeoutCancellationToken.CancelAfter(timeout.Value);

                using (var socket = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                {
                    var secureStream = default(SslStream);
                    var networkStream = default(Stream);

                    try
                    {
                        // 연결
                        var connectTask = socket.ConnectAsync(ipEndPoint);
                        var connectResultTask = await Task
                            .WhenAny(connectTask, Task.Delay(Timeout.Infinite, timeoutCancellationToken.Token))
                            .ConfigureAwait(false);
                        if (!object.ReferenceEquals(connectTask, connectResultTask))
                            throw new TimeoutException("Connection timeout");

                        var stream = new NetworkStream(socket, false);

                        if (protocol.RequireSsl)
                        {
                            if (remoteCertificateValidationCallback == null)
                                remoteCertificateValidationCallback = ValidateServerCertificate;
                            secureStream = new SslStream(stream, false, remoteCertificateValidationCallback);
                            await secureStream.AuthenticateAsClientAsync(ipAddress.ToString()).ConfigureAwait(false);
                            networkStream = secureStream;
                        }
                        else
                            networkStream = stream;

                        if (protocol is ITcpSendFirstProtocol sendFirstProtocol)
                        {
                            byte[] handshakePacket = sendFirstProtocol.GetInitialSendData();
                            if (handshakePacket != null && handshakePacket.Length > 0)
                            {
                                // 데이터 전송
                                var sendTask = networkStream.WriteAsync(handshakePacket, 0, handshakePacket.Length, timeoutCancellationToken.Token);
                                var sendResultTask = await Task
                                    .WhenAny(sendTask, Task.Delay(Timeout.Infinite, timeoutCancellationToken.Token))
                                    .ConfigureAwait(false);
                                if (!object.ReferenceEquals(sendTask, sendResultTask))
                                    throw new TimeoutException("Send timeout");
                                await sendTask.ConfigureAwait(false);

                                // 데이터 수신
                                var readTask = networkStream.ReadAsync(buffer, 0, buffer.Length, timeoutCancellationToken.Token);
                                var readResultTask = await Task
                                    .WhenAny(readTask, Task.Delay(Timeout.Infinite, timeoutCancellationToken.Token))
                                    .ConfigureAwait(false);
                                if (!object.ReferenceEquals(readTask, readResultTask))
                                    throw new TimeoutException("Receive timeout");
                                var read = await readTask.ConfigureAwait(false);
                                if (read < 1) return false;
                            }

                            return true;
                        }
                        else if (protocol is ITcpReceiveFirstProtocol receiveFirstProtocol)
                        {
                            // 데이터 수신
                            var readTask = networkStream.ReadAsync(buffer, 0, buffer.Length, timeoutCancellationToken.Token);
                            var readResultTask = await Task
                                .WhenAny(readTask, Task.Delay(Timeout.Infinite, timeoutCancellationToken.Token))
                                .ConfigureAwait(false);
                            if (!object.ReferenceEquals(readTask, readResultTask))
                                throw new TimeoutException("Receive timeout");
                            var read = await readTask.ConfigureAwait(false);
                            if (read < 1) return false;

                            var pattern = receiveFirstProtocol.GetExpectedInitialReceiveData();
                            return buffer.Take(pattern.Length).SequenceEqual(pattern);
                        }
                        else
                        {
                            return false;
                        }
                    }
                    catch (Exception thrownException)
                    {
                        exceptionHandler?.Invoke(thrownException);
                        return false;
                    }
                    finally
                    {
                        if (secureStream != null)
                            secureStream.Dispose();
                        if (networkStream != null)
                            networkStream.Dispose();
                        if (socket.Connected)
                        {
                            socket.Shutdown(SocketShutdown.Both);
                            socket.Close();
                        }
                    }
                }
            }
        }
    }
}
