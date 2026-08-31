using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Telnyx.PublicKeys.Registrars;
using Soenneker.Telnyx.Validators.Signatures.Abstract;

namespace Soenneker.Telnyx.Validators.Signatures.Registrars;

/// <summary>
/// Registers Telnyx webhook-signature validation.
/// </summary>
public static class TelnyxSignatureValidatorRegistrar
{
    /// <summary>
    /// Adds <see cref="ITelnyxSignatureValidator"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddTelnyxSignatureValidatorAsSingleton(this IServiceCollection services)
    {
        services.AddTelnyxPublicKeysUtilAsSingleton()
                .TryAddSingleton<ITelnyxSignatureValidator, TelnyxSignatureValidator>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="ITelnyxSignatureValidator"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddTelnyxSignatureValidatorAsScoped(this IServiceCollection services)
    {
        services.AddTelnyxPublicKeysUtilAsSingleton()
                .TryAddScoped<ITelnyxSignatureValidator, TelnyxSignatureValidator>();

        return services;
    }
}
