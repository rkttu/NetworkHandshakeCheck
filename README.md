# NetworkHandshakeCheck

A framework that helps you communicate with servers over arbitrary network protocols, including well-known ones, and check the status of their responses.

## How to use

Initializes an instance of a class containing specifications for the protocol and calls the `TestTcpHandshakeAsync` extension method.

```csharp
// HTTP
var http = new HttpHandshakeProtocol();
var result = await http.TestTcpHandshakeAsync("www.example.com");
Assert.NotNull(result);

// HTTPS
var https = new HttpsHandshakeProtocol();
var result = await https.TestTcpHandshakeAsync("www.microsoft.com");
Assert.NotNull(result);

// RDP
var rdp = new SshHandshakeProtocol();
var result = await rdp.TestTcpHandshakeAsync("test.rebex.net");
Assert.NotNull(result);
```

## How to implement custom protocol support

### Send first protocol

If the protocol requires sending a message to the server as soon as the client connects, implement it as follows.

```csharp
public sealed class VncHandshakeProtocol : ITcpSendFirstProtocol
{
    public string ProtocolName => "VNC";

    public int DefaultPort => 5900;

    public bool RequireSsl => false;

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
```

### Receive first protocol

If the server sends a banner message or confirmation message after confirming the client's connection, implement it as follows.

```csharp
public sealed class SshHandshakeProtocol : ITcpReceiveFirstProtocol
{
    public string ProtocolName => "SSH";

    public int DefaultPort => 22;

    public bool RequireSsl => false;

    public byte[] GetExpectedInitialReceiveData() =>
        new byte[] { 0x53, 0x53, 0x48, 0x2d, };
}
```

### Handling SSL connection

If the SSL protocol handshake must be performed immediately after connection, such as HTTPS, SSL processing will be performed automatically if the RequireSsl property is returned as true.

```csharp
public sealed class HttpsHandshakeProtocol : ITcpSendFirstProtocol
{
    public string ProtocolName => "HTTPS";

    public int DefaultPort => 443;

    public bool RequireSsl => true;

    public byte[] GetInitialSendData() =>
        new byte[] { 0x47, 0x45, 0x54, 0x20, 0x2F, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A, 0x0D, 0x0A, };
}
```

## License

This library follows Apache-2.0 license. See [LICENSE](./LICENSE) file for more information.
