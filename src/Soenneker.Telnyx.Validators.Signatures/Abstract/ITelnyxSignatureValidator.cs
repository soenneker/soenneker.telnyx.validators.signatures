using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Telnyx.Validators.Signatures.Abstract;

/// <summary>
/// Validates Telnyx webhook signatures.
/// </summary>
public interface ITelnyxSignatureValidator
{
    /// <summary>
    /// Validates a Telnyx webhook signature.
    /// </summary>
    /// <remarks>
    /// <paramref name="payload"/> must be the raw request body. Parsing and reserializing the body before validation can change
    /// its bytes and invalidate an otherwise valid signature.
    /// </remarks>
    /// <param name="payload">The raw webhook request body.</param>
    /// <param name="signature">The value of the <c>telnyx-signature-ed25519</c> header.</param>
    /// <param name="timestamp">The value of the <c>telnyx-timestamp</c> header.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="true"/> when the signature is valid; otherwise, <see langword="false"/>.</returns>
    ValueTask<bool> Validate(string payload, string signature, string timestamp, CancellationToken cancellationToken = default);
}
