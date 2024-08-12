namespace NetworkHandshakeCheck.Test
{
    public class TcpHandshakeTest
    {
        [Fact]
        public async Task HttpTest()
        {
            var http = new HttpHandshakeProtocol();
            var result = await http.TestTcpHandshakeAsync("www.example.com");
            Assert.NotNull(result);
        }

        [Fact]
        public async Task HttpsTest()
        {
            var https = new HttpsHandshakeProtocol();
            var result = await https.TestTcpHandshakeAsync("www.microsoft.com");
            Assert.NotNull(result);
        }

        [Fact]
        public async Task SshTest()
        {
            var rdp = new SshHandshakeProtocol();
            var result = await rdp.TestTcpHandshakeAsync("test.rebex.net");
            Assert.NotNull(result);
        }
    }
}
