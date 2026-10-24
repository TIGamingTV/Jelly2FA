using System;
using Jellyfin.Data.Events.Users;
using Jellyfin.Plugin.Jelly2FA.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.Jelly2FA;

/// <summary>
/// Registers Jelly2FA services with Jellyfin's DI container.
/// </summary>
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.TryAddSingleton(TimeProvider.System);
        serviceCollection.AddHttpContextAccessor();

        serviceCollection.AddSingleton<IConfigProvider, PluginConfigProvider>();
        serviceCollection.AddSingleton<HealthState>();
        serviceCollection.AddSingleton<ChallengeStore>();
        serviceCollection.AddSingleton<RateLimiter>();
        serviceCollection.AddSingleton<ThrottleService>();
        serviceCollection.AddSingleton<LoginApprovalRegistry>();
        serviceCollection.AddSingleton<SecretStore>();
        serviceCollection.AddSingleton<IOriginClassifier, OriginClassifier>();
        serviceCollection.AddSingleton<IEmailSender, SmtpEmailSender>();
        serviceCollection.AddSingleton<EmailQueue>();
        serviceCollection.AddSingleton<IHostedService>(sp => sp.GetRequiredService<EmailQueue>());
        serviceCollection.AddSingleton<INotificationService, NotificationService>();
        serviceCollection.AddSingleton<SuspensionStore>();
        serviceCollection.AddSingleton<EnrollmentService>();
        serviceCollection.AddSingleton<PluginStateService>();
        serviceCollection.AddHostedService<ReactivationStartupService>();
        serviceCollection.AddSingleton<HealthService>();
        serviceCollection.AddHostedService<SelfCheckService>();

        // Enforcement point: Jellyfin's UserManager receives every registered IAuthenticationProvider.
        serviceCollection.AddSingleton<IAuthenticationProvider, TwoFactorAuthenticationProvider>();

        // Captures the raw TCP peer before Jellyfin's forwarded-headers middleware rewrites it.
        serviceCollection.AddTransient<IStartupFilter, OriginCaptureStartupFilter>();

        serviceCollection.AddScoped<IEventConsumer<AuthenticationResultEventArgs>, TokenWatcher>();
        serviceCollection.AddScoped<IEventConsumer<UserPasswordChangedEventArgs>, PasswordChangedConsumer>();
        serviceCollection.AddScoped<IEventConsumer<UserDeletedEventArgs>, UserDeletedConsumer>();
    }
}
