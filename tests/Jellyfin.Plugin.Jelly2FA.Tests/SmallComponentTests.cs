using Jellyfin.Plugin.Jelly2FA.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using System.Security.Claims;
using Xunit;

namespace Jellyfin.Plugin.Jelly2FA.Tests;

public class RateLimiterTests
{
    [Fact]
    public void Limit_AndWindowExpiry()
    {
        var time = new FakeTimeProvider();
        var limiter = new RateLimiter(time);
        var window = TimeSpan.FromMinutes(5);
        for (var i = 0; i < 3; i++)
        {
            Assert.False(limiter.IsLimited("k", 3, window));
            limiter.Record("k", window);
        }

        Assert.True(limiter.IsLimited("k", 3, window));
        Assert.False(limiter.IsLimited("other", 3, window));
        time.Advance(window);
        Assert.False(limiter.IsLimited("k", 3, window));
    }

    [Fact]
    public void TryAcquire_RespectsBudget()
    {
        var limiter = new RateLimiter(new FakeTimeProvider());
        Assert.True(limiter.TryAcquire("mail", 2, TimeSpan.FromHours(1)));
        Assert.True(limiter.TryAcquire("mail", 2, TimeSpan.FromHours(1)));
        Assert.False(limiter.TryAcquire("mail", 2, TimeSpan.FromHours(1)));
    }
}

public class LoginEndpointsTests
{
    private static HttpContext Ctx(string method, string path, bool authenticated = false)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        if (authenticated)
        {
            ctx.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("x", "y") }, "test"));
        }

        return ctx;
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/users/authenticatebyname")]
    [InlineData("/Users/AuthenticateByName/")]
    [InlineData("/Users/0f8fad5b-d9cb-469f-a165-70867728950e/Authenticate")]
    [InlineData("/Users/0f8fad5bd9cb469fa16570867728950e/Authenticate")]
    public void LoginPaths(string path) => Assert.Equal(LoginKind.Login, LoginEndpoints.Classify(Ctx("POST", path)));

    [Theory]
    [InlineData("GET", "/Users/AuthenticateByName")]
    [InlineData("POST", "/Users/AuthenticateWithQuickConnect")]
    [InlineData("POST", "/Users/ForgotPassword")]
    [InlineData("POST", "/Some/Plugin/Login")]
    [InlineData("POST", "/Users/Password")] // unauthenticated password check is not allowed
    public void OtherCallers_AreUnknown(string method, string path) => Assert.Equal(LoginKind.Unknown, LoginEndpoints.Classify(Ctx(method, path)));

    [Fact]
    public void NoHttpContext_IsUnknown() => Assert.Equal(LoginKind.Unknown, LoginEndpoints.Classify(null));

    [Theory]
    [InlineData("/Users/Password")]
    [InlineData("/Users/0f8fad5b-d9cb-469f-a165-70867728950e/Password")]
    public void PasswordChange_IsPasswordCheck(string path) => Assert.Equal(LoginKind.PasswordCheck, LoginEndpoints.Classify(Ctx("POST", path, authenticated: true)));

    [Fact]
    public void QuickConnectAuthorize_Detected()
    {
        Assert.True(LoginEndpoints.IsQuickConnectAuthorize(Ctx("POST", "/QuickConnect/Authorize")));
        Assert.False(LoginEndpoints.IsQuickConnectAuthorize(Ctx("POST", "/QuickConnect/Initiate")));
    }
}

public class CodeSplitTests
{
    [Theory]
    [InlineData("secret12345678", "secret", "12345678")]
    [InlineData("pw 0000000000", "pw 00", "00000000")]
    public void Splits(string input, string pw, string code)
    {
        Assert.True(TwoFactorAuthenticationProvider.TrySplitCode(input, out var p, out var c));
        Assert.Equal(pw, p);
        Assert.Equal(code, c);
    }

    [Theory]
    [InlineData("12345678")]
    [InlineData("secret1234567x")]
    [InlineData("secret")]
    [InlineData("")]
    [InlineData("secret１２３４５６７８")] // full-width digits are not codes
    public void DoesNotSplit(string input) => Assert.False(TwoFactorAuthenticationProvider.TrySplitCode(input, out _, out _));
}

public class EmailAddressTests
{
    [Theory]
    [InlineData("alice@example.com", true)]
    [InlineData("a.b+tag@sub.example.org", true)]
    [InlineData("", false)]
    [InlineData("not-an-address", false)]
    [InlineData("alice@example.com\r\nBcc: evil@example.com", false)]
    [InlineData("Alice <alice@example.com>", false)]
    [InlineData("a@example.com,b@example.com", false)]
    public void Validation(string value, bool valid) => Assert.Equal(valid, EmailAddress.IsValid(value));

    [Fact]
    public void SingleLine_StripsControlCharacters()
        => Assert.DoesNotContain('\n', EmailAddress.SingleLine("Server\r\nBcc: x@y"));
}

public class NotificationTemplateTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-17T12:00:00Z");

    private static EmailMessage Code(string? lang, bool codeOnly = false, string user = "alice", string device = "Phone")
        => NotificationService.BuildCodeEmail(lang, codeOnly, "MyServer", "a@example.com", user, "12345678", device, "App", "203.0.113.5", 10, Now);

    [Fact]
    public void English_IsDefault_AndHtmlHighlightsCode()
    {
        var m = Code(null);
        Assert.Equal("MyServer: sign-in code", m.Subject);
        Assert.Contains("Hello alice,", m.Body, StringComparison.Ordinal);
        Assert.Contains("12345678", m.Body, StringComparison.Ordinal);
        Assert.Contains("MyPassword12345678", m.Body, StringComparison.Ordinal);
        Assert.NotNull(m.HtmlBody);
        Assert.Contains("font-weight:bold", m.HtmlBody, StringComparison.Ordinal);
        Assert.Contains(">12345678</span>", m.HtmlBody, StringComparison.Ordinal);
        Assert.Equal(Code("xx").Subject, m.Subject); // unknown language falls back to English
    }

    [Fact]
    public void German_Texts()
    {
        var m = Code("de");
        Assert.Equal("MyServer: Anmeldecode", m.Subject);
        Assert.Contains("Hallo alice,", m.Body, StringComparison.Ordinal);
        Assert.Contains("MeinPasswort12345678", m.Body, StringComparison.Ordinal);
        Assert.Contains("Gerät:", m.Body, StringComparison.Ordinal);
        Assert.Contains("Ger&#228;t", m.HtmlBody, StringComparison.Ordinal); // HtmlEncode escapes non-ASCII
    }

    [Fact]
    public void CodeOnly_ChangesInstructions()
    {
        Assert.DoesNotContain("MyPassword", Code("en", codeOnly: true).Body, StringComparison.Ordinal);
        Assert.Contains("only this code", Code("en", codeOnly: true).Body, StringComparison.Ordinal);
        Assert.Contains("nur diesen Code", Code("de", codeOnly: true).Body, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_IsEncoded()
    {
        var m = Code("en", user: "<b>x</b>", device: "<script>alert(1)</script>");
        Assert.DoesNotContain("<script>", m.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("<b>x</b>", m.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", m.HtmlBody, StringComparison.Ordinal);
    }

    [Fact]
    public void QuickConnect_German()
    {
        var m = NotificationService.BuildQuickConnectEmail("de", "MyServer", "a@example.com", "alice", "Phone", "App", "203.0.113.5", Now);
        Assert.Equal("MyServer: neue Anmeldung per Quick Connect", m.Subject);
        Assert.Contains("Freigegeben von IP: 203.0.113.5", m.Body, StringComparison.Ordinal);
        Assert.Null(m.HtmlBody);
    }

    private static TimeZoneInfo Berlin => TimeZoneInfo.FindSystemTimeZoneById("Europe/Berlin");

    [Fact]
    public void Time_Utc()
    {
        Assert.Equal("2026-10-17 12:00 UTC", NotificationService.FormatTime(Now, null));
        Assert.Equal("2026-10-17 12:00 UTC", NotificationService.FormatTime(Now, TimeZoneInfo.Utc));
        Assert.Equal("2026-10-17 12:00 UTC", NotificationService.FormatTime(Now, TimeZoneInfo.FindSystemTimeZoneById("Etc/UTC")));
    }

    [Fact]
    public void Time_Berlin_SummerAndWinter()
    {
        Assert.Equal("2026-10-17 14:00 Europe/Berlin (UTC+02:00)", NotificationService.FormatTime(Now, Berlin));
        Assert.Equal("2026-12-01 13:30 Europe/Berlin (UTC+01:00)", NotificationService.FormatTime(DateTimeOffset.Parse("2026-12-01T12:30:00Z"), Berlin));
    }

    [Fact]
    public void Time_NegativeOffset()
        => Assert.Equal("2026-10-17 08:00 America/New_York (UTC-04:00)", NotificationService.FormatTime(Now, TimeZoneInfo.FindSystemTimeZoneById("America/New_York")));

    [Fact]
    public void Time_ZoneWithoutName_ShowsOffsetOnly()
    {
        var custom = TimeZoneInfo.CreateCustomTimeZone("Local", TimeSpan.FromHours(3), "x", "x");
        Assert.Equal("2026-10-17 15:00 (UTC+03:00)", NotificationService.FormatTime(Now, custom));
    }

    [Fact]
    public void TimeZone_Resolution()
    {
        var server = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
        Assert.Same(server, NotificationService.ResolveTimeZone(null, server, out var invalid));
        Assert.False(invalid);
        Assert.Same(server, NotificationService.ResolveTimeZone("  ", server, out invalid));
        Assert.False(invalid);
        Assert.Equal("Europe/Berlin", NotificationService.ResolveTimeZone(" Europe/Berlin ", server, out invalid).Id);
        Assert.False(invalid);
        Assert.Same(server, NotificationService.ResolveTimeZone("Mars/Olympus", server, out invalid));
        Assert.True(invalid);
    }

    [Fact]
    public void CodeEmail_UsesTimeZone()
    {
        var m = NotificationService.BuildCodeEmail("en", false, "S", "a@example.com", "alice", "12345678", "Phone", "App", "203.0.113.5", 10, Now, Berlin);
        Assert.Contains("2026-10-17 14:00 Europe/Berlin (UTC+02:00)", m.Body, StringComparison.Ordinal);
        Assert.Contains("2026-10-17 14:00 Europe/Berlin (UTC+02:00)", m.HtmlBody, StringComparison.Ordinal);
        Assert.DoesNotContain("UTC</td>", m.HtmlBody, StringComparison.Ordinal);
    }

    [Fact]
    public void QuickConnectEmail_UsesTimeZone()
    {
        var m = NotificationService.BuildQuickConnectEmail("en", "S", "a@example.com", "alice", "Phone", "App", "203.0.113.5", Now, Berlin);
        Assert.Contains("2026-10-17 14:00 Europe/Berlin (UTC+02:00)", m.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CodeEmail_MentionsReuse()
    {
        Assert.DoesNotContain("Exception:", Code("en").Body, StringComparison.Ordinal);
        var reuse = new ReuseInfo(2, 5, new[] { "Seerr", "Jellyseerr" });
        var en = NotificationService.BuildCodeEmail("en", true, "S", "a@example.com", "alice", "12345678", "Phone", "App", "203.0.113.5", 10, Now, null, reuse);
        Assert.Contains("for 5 minutes after you signed in with it, these apps may use the code 2 more time(s)", en.Body, StringComparison.Ordinal);
        Assert.Contains("Seerr, Jellyseerr", en.Body, StringComparison.Ordinal);
        var de = NotificationService.BuildCodeEmail("de", true, "S", "a@example.com", "alice", "12345678", "Phone", "App", "203.0.113.5", 10, Now, null, reuse);
        Assert.Contains("noch 2-mal verwenden", de.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void ReuseInfo_FromConfig()
    {
        var c = new Jellyfin.Plugin.Jelly2FA.Configuration.PluginConfiguration();
        Assert.Null(ReuseInfo.From(c)); // off by default
        c.CodeReuseCount = 99;
        c.CodeReuseMinutes = 0;
        var r = ReuseInfo.From(c);
        Assert.NotNull(r);
        Assert.Equal(CodeReusePolicy.MaxCount, r!.Count);
        Assert.Equal(1, r.Minutes);
        Assert.Equal(new[] { "Seerr", "Jellyseerr" }, r.Clients);
    }
}

public class CodeReusePolicyTests
{
    [Fact]
    public void Clients_CaseInsensitiveExactMatch()
    {
        var c = new Jellyfin.Plugin.Jelly2FA.Configuration.PluginConfiguration { CodeReuseCount = 1, CodeReuseClients = "Seerr; jellyseerr ,seerr" };
        Assert.Equal(new[] { "Seerr", "jellyseerr" }, CodeReusePolicy.Clients(c));
        Assert.True(CodeReusePolicy.AllowsClient(c, "seerr"));
        Assert.True(CodeReusePolicy.AllowsClient(c, " Jellyseerr "));
        Assert.False(CodeReusePolicy.AllowsClient(c, "Seerr2"));
        Assert.False(CodeReusePolicy.AllowsClient(c, null));
        c.CodeReuseCount = 0;
        Assert.False(CodeReusePolicy.AllowsClient(c, "Seerr"));
    }

    [Fact]
    public void Peer_FilteredByAddresses()
    {
        var c = new Jellyfin.Plugin.Jelly2FA.Configuration.PluginConfiguration();
        Assert.True(CodeReusePolicy.AllowsPeer(c, null)); // no list: any
        c.CodeReuseAddresses = "10.0.0.5, 172.18.0.0/16";
        Assert.True(CodeReusePolicy.AllowsPeer(c, System.Net.IPAddress.Parse("10.0.0.5")));
        Assert.True(CodeReusePolicy.AllowsPeer(c, System.Net.IPAddress.Parse("::ffff:172.18.3.4")));
        Assert.False(CodeReusePolicy.AllowsPeer(c, System.Net.IPAddress.Parse("10.0.0.6")));
        Assert.False(CodeReusePolicy.AllowsPeer(c, null));
    }
}
