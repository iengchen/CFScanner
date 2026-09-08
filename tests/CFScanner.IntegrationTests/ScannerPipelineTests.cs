using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.IntegrationTests;

public sealed class ScannerPipelineTests : IDisposable
{
    private readonly string _tempDir;

    public ScannerPipelineTests()
    {
        TestState.Reset();
        _tempDir = Path.Combine(Path.GetTempPath(), $"cfscanner-pipeline-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        TestState.Reset();
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task ProducerWorker_OpenLoopbackPort_ForwardsLiveConnection()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepted = listener.AcceptTcpClientAsync();
        var channel = Channel.CreateUnbounded<ScannerWorkers.LiveConnection>();

        await ScannerWorkers.ProducerWorker(IPAddress.Loopback, port, channel.Writer, CancellationToken.None);

        var live = await channel.Reader.ReadAsync(TestContext.Current.CancellationToken);
        using var serverClient = await accepted.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal(IPAddress.Loopback, live.Ip);
            Assert.Equal(port, live.Port);
            Assert.True(live.Client.Connected);
            Assert.Equal(1, GlobalContext.TcpOpenTotal);
            Assert.Equal(0, GlobalContext.ScannedCount);
        }
        finally
        {
            live.Client.Dispose();
        }
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task ProducerWorker_ClosedLoopbackPort_CountsAttemptAndDoesNotForward()
    {
        int port;
        using (var listener = new TcpListener(IPAddress.Loopback, 0))
        {
            listener.Start();
            port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        GlobalContext.Config.TcpTimeoutMs = 500;
        var channel = Channel.CreateUnbounded<ScannerWorkers.LiveConnection>();
        await ScannerWorkers.ProducerWorker(IPAddress.Loopback, port, channel.Writer, CancellationToken.None);

        Assert.False(channel.Reader.TryRead(out _));
        Assert.Equal(0, GlobalContext.TcpOpenTotal);
        Assert.Equal(1, GlobalContext.ScannedCount);
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task SignatureWorker_CloudflareLikeTlsResponse_ForwardsSignatureResult()
    {
        await using var server = await TlsResponseServer.StartAsync(
            "HTTP/1.1 200 OK\r\nServer: CloudFlare\r\nCF-Ray: test\r\nContent-Length: 0\r\n\r\n",
            connectionCount: 1);
        GlobalContext.Config.V2RayConfigPath = "enabled-for-channel-test";
        var input = Channel.CreateUnbounded<ScannerWorkers.LiveConnection>();
        var output = Channel.CreateUnbounded<ScannerWorkers.SignatureResult>();

        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port, TestContext.Current.CancellationToken);
        await input.Writer.WriteAsync(
            new ScannerWorkers.LiveConnection(IPAddress.Loopback, server.Port, client),
            TestContext.Current.CancellationToken);
        input.Writer.Complete();

        await ScannerWorkers.ConsumerWorker_Signature(
            input.Reader, output.Writer, TestContext.Current.CancellationToken);

        var result = await output.Reader.ReadAsync(TestContext.Current.CancellationToken);
        Assert.Equal(IPAddress.Loopback, result.Ip);
        Assert.Equal(server.Port, result.Port);
        Assert.True(result.SignatureLatency >= 0);
        Assert.Equal(1, GlobalContext.SignaturePassed);
        Assert.Equal(1, GlobalContext.ScannedCount);
        await server.Completion.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task SignatureWorker_RetriesAfterInvalidResponse_AndAcceptsSecondResponse()
    {
        await using var server = await TlsResponseServer.StartAsync(
            "HTTP/1.1 404 Not Found\r\nServer: cloudflare\r\nCF-Ray: first\r\n\r\n",
            "HTTP/1.1 200 OK\r\nserver: cloudflare\r\ncf-ray: second\r\n\r\n");
        GlobalContext.Config.V2RayConfigPath = "enabled-for-channel-test";
        var input = Channel.CreateUnbounded<ScannerWorkers.LiveConnection>();
        var output = Channel.CreateUnbounded<ScannerWorkers.SignatureResult>();

        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port, TestContext.Current.CancellationToken);
        await input.Writer.WriteAsync(
            new ScannerWorkers.LiveConnection(IPAddress.Loopback, server.Port, client),
            TestContext.Current.CancellationToken);
        input.Writer.Complete();

        await ScannerWorkers.ConsumerWorker_Signature(
            input.Reader, output.Writer, TestContext.Current.CancellationToken);

        Assert.True(output.Reader.TryRead(out var result));
        Assert.Equal(server.Port, result.Port);
        Assert.Equal(1, GlobalContext.SignaturePassed);
        Assert.Equal(1, GlobalContext.ScannedCount);
        await server.Completion.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task ScanEngine_LoopbackCloudflareResponse_WritesOneResultAndDrainsPipeline()
    {
        await using var server = await TlsResponseServer.StartAsync(
            "HTTP/1.1 200 OK\r\nserver: cloudflare\r\ncf-ray: pipeline\r\n\r\n",
            connectionCount: 1);
        GlobalContext.Config.Ports = [server.Port];
        GlobalContext.Config.TcpWorkers = 1;
        GlobalContext.Config.SignatureWorkers = 1;
        GlobalContext.Config.TcpChannelBuffer = 1;
        GlobalContext.Config.SaveLatency = false;
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "pipeline.txt");

        await ScanEngine.RunScanAsync([IPAddress.Loopback]);

        Assert.Equal(1, GlobalContext.TcpOpenTotal);
        Assert.Equal(1, GlobalContext.SignaturePassed);
        Assert.Equal(1, GlobalContext.ScannedCount);
        Assert.Equal("127.0.0.1", File.ReadAllText(GlobalContext.OutputFilePath).Trim());
        Assert.True(GlobalContext.Cts.IsCancellationRequested);
        await server.Completion.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task ScanEngine_ResumeBetweenPorts_SkipsCompletedEndpoint()
    {
        await using var firstServer = await TlsResponseServer.StartAsync(
            "HTTP/1.1 200 OK\r\nserver: cloudflare\r\ncf-ray: first\r\n\r\n",
            connectionCount: 0);
        await using var secondServer = await TlsResponseServer.StartAsync(
            "HTTP/1.1 200 OK\r\nserver: cloudflare\r\ncf-ray: second\r\n\r\n",
            connectionCount: 1);
        GlobalContext.Config.Ports = [firstServer.Port, secondServer.Port];
        GlobalContext.Config.TcpWorkers = 1;
        GlobalContext.Config.SignatureWorkers = 1;
        GlobalContext.Config.TcpChannelBuffer = 1;
        GlobalContext.Config.SaveLatency = false;
        GlobalContext.ResumeCursor = 1;
        GlobalContext.InitializeResumeProgress(1);
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "resume-between-ports.txt");

        await ScanEngine.RunScanAsync([IPAddress.Loopback]);

        Assert.Equal(1, GlobalContext.TcpOpenTotal);
        Assert.Equal(1, GlobalContext.SignaturePassed);
        Assert.Equal(1, GlobalContext.ScannedCount);
        Assert.Equal("127.0.0.1:" + secondServer.Port,
            File.ReadAllText(GlobalContext.OutputFilePath).Trim());
        await secondServer.Completion.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 10_000), Trait("Category", "Integration")]
    public async Task ScanEngine_ResultWriteFailure_CancelsAndPropagatesAfterCleanup()
    {
        await using var server = await TlsResponseServer.StartAsync(
            "HTTP/1.1 200 OK\r\nserver: cloudflare\r\ncf-ray: write-failure\r\n\r\n",
            connectionCount: 1);
        GlobalContext.Config.Ports = [server.Port];
        GlobalContext.Config.TcpWorkers = 1;
        GlobalContext.Config.SignatureWorkers = 1;
        GlobalContext.Config.TcpChannelBuffer = 1;
        GlobalContext.OutputFilePath = _tempDir;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            ScanEngine.RunScanAsync([IPAddress.Loopback]).WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.True(GlobalContext.Cts.IsCancellationRequested);
        await server.Completion.WaitAsync(TestContext.Current.CancellationToken);
    }

    private sealed class TlsResponseServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;
        private readonly string[] _responses;

        private TlsResponseServer(TcpListener listener, X509Certificate2 certificate, string[] responses)
        {
            _listener = listener;
            _certificate = certificate;
            _responses = responses;
            Completion = ServeAsync();
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public Task Completion { get; }

        public static Task<TlsResponseServer> StartAsync(string response, int connectionCount) =>
            StartAsync(Enumerable.Repeat(response, connectionCount).ToArray());

        public static Task<TlsResponseServer> StartAsync(params string[] responses)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return Task.FromResult(new TlsResponseServer(listener, CreateCertificate(), responses));
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            try { await Completion.WaitAsync(TimeSpan.FromSeconds(2)); }
            catch (OperationCanceledException) { }
            catch (TimeoutException) { }
            _certificate.Dispose();
        }

        private async Task ServeAsync()
        {
            try
            {
                foreach (var response in _responses)
                {
                    using var client = await _listener.AcceptTcpClientAsync();
                    await using var network = client.GetStream();
                    await using var tls = new SslStream(network, leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateRequired = false
                    });

                    var buffer = new byte[4096];
                    var request = new List<byte>();
                    while (request.Count < 16 * 1024)
                    {
                        int read = await tls.ReadAsync(buffer);
                        if (read == 0) break;
                        request.AddRange(buffer.AsSpan(0, read).ToArray());
                        if (request.Count >= 4 &&
                            request.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray()))
                            break;
                    }

                    await tls.WriteAsync(System.Text.Encoding.ASCII.GetBytes(response));
                    await tls.FlushAsync();
                }
            }
            catch (SocketException) when (!_listener.Server.IsBound)
            {
            }
        }

        private static X509Certificate2 CreateCertificate()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=localhost",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using var generated = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddDays(1));
            return X509CertificateLoader.LoadPkcs12(
                generated.Export(X509ContentType.Pfx),
                password: null,
                X509KeyStorageFlags.DefaultKeySet);
        }
    }
}
