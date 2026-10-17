using System.Net;
using Jellyfin.Plugin.Jelly2FA.Configuration;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Configuration;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

public class OriginClassifierTests
{
    private readonly PluginConfiguration _config = new();
    private readonly NetworkConfiguration _network = new() { KnownProxies = new[] { "192.168.1.10" } };
    private readonly INetworkManager _networkManager = Substitute.For<INetworkManager>();

    public OriginClassifierTests()
    {
        // Emulate Jellyfin's LAN = 192.168.1.0/24.
        _networkManager.IsInLocalNetwork(Arg.Any<IPAddress>())
            .Returns(ci => IPNetwork.Parse("192.168.1.0/24").Contains(ci.Arg<IPAddress>()) || IPAddress.IsLoopback(ci.Arg<IPAddress>()));
    }

    private OriginClassifier Classifier()
    {
        var server = Substitute.For<IServerConfigurationManager>();
        server.GetConfiguration(Arg.Any<string>()).Returns(_network);
        var cfg = new TestConfigProvider(_config);
        return new OriginClassifier(_networkManager, server, cfg);
    }

    private static RequestOrigin Direct(string ip) => new(IPAddress.Parse(ip), false);

    [Fact]
    public void MissingCapture_Requires2Fa() => Assert.False(Classifier().Classify(null).TrustedDirect);

    [Fact]
    public void LanDirect_IsTrusted() => Assert.True(Classifier().Classify(Direct("192.168.1.50")).TrustedDirect);

    [Fact]
    public void IPv4MappedLan_IsTrusted() => Assert.True(Classifier().Classify(Direct("::ffff:192.168.1.50")).TrustedDirect);

    [Theory]
    [InlineData("100.100.110.5")]
    [InlineData("100.64.0.1")]
    [InlineData("fd7a:115c:a1e0::1")]
    public void TailscaleDirect_IsTrustedByDefault(string ip) => Assert.True(Classifier().Classify(Direct(ip)).TrustedDirect);

    [Fact]
    public void Proxy_Requires2Fa() => Assert.False(Classifier().Classify(Direct("192.168.1.10")).TrustedDirect);

    [Fact]
    public void PluginProxyAddressCidr_Requires2Fa()
    {
        _config.ProxyAddresses = "192.168.1.0/28";
        Assert.False(Classifier().Classify(Direct("192.168.1.5")).TrustedDirect);
    }

    [Fact]
    public void ForwardingHeaders_Require2Fa_EvenFromLan()
        => Assert.False(Classifier().Classify(new RequestOrigin(IPAddress.Parse("192.168.1.50"), true)).TrustedDirect);

    [Fact]
    public void PublicAddress_Requires2Fa() => Assert.False(Classifier().Classify(Direct("203.0.113.7")).TrustedDirect);

    [Fact]
    public void Loopback_NotTrustedByDefault() => Assert.False(Classifier().Classify(Direct("127.0.0.1")).TrustedDirect);

    [Fact]
    public void Loopback_TrustedWhenEnabled()
    {
        _config.TrustLoopback = true;
        Assert.True(Classifier().Classify(Direct("127.0.0.1")).TrustedDirect);
    }

    [Fact]
    public void NoProxyConfigured_FailsClosedForEveryone()
    {
        _network.KnownProxies = Array.Empty<string>();
        var classifier = Classifier();
        Assert.False(classifier.ProxyConfigured);
        Assert.False(classifier.Classify(Direct("192.168.1.50")).TrustedDirect);
        Assert.False(classifier.Classify(Direct("100.100.110.5")).TrustedDirect);
    }

    [Fact]
    public void LanTrustCanBeDisabled()
    {
        _config.TrustJellyfinLocalNetworks = false;
        Assert.False(Classifier().Classify(Direct("192.168.1.50")).TrustedDirect);
        Assert.True(Classifier().Classify(Direct("100.100.110.5")).TrustedDirect);
    }

    [Fact]
    public void InvalidListEntries_AreIgnored()
    {
        var nets = OriginClassifier.ParseNetworks("10.0.0.0/8, nonsense, ,fe80::1 ; 999.1.1.1");
        Assert.Equal(2, nets.Count);
    }
}

internal sealed class TestConfigProvider : IConfigProvider
{
    public TestConfigProvider(PluginConfiguration config) => Current = config;

    public PluginConfiguration Current { get; private set; }

    public void Save(PluginConfiguration configuration) => Current = configuration;
}
