using Microsoft.Extensions.Logging;
using Soenneker.Cryptography.Ed25519;
using Soenneker.Extensions.ValueTask;
using Soenneker.Telnyx.PublicKeys.Abstract;
using Soenneker.Telnyx.Validators.Signatures.Abstract;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Telnyx.Validators.Signatures;

public sealed class TelnyxSignatureValidator : ITelnyxSignatureValidator
{
    private const long _timestampToleranceSeconds = 300;

    private readonly ITelnyxPublicKeysUtil _publicKeysUtil;
    private readonly ILogger<TelnyxSignatureValidator> _logger;

    public TelnyxSignatureValidator(ITelnyxPublicKeysUtil publicKeysUtil, ILogger<TelnyxSignatureValidator> logger)
    {
        _publicKeysUtil = publicKeysUtil;
        _logger = logger;
    }

    public async ValueTask<bool> Validate(string payload, string signature, string timestamp, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(payload) || string.IsNullOrWhiteSpace(signature) || string.IsNullOrWhiteSpace(timestamp))
            return false;

        if (!long.TryParse(timestamp, out long timestampSeconds))
            return false;

        long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (timestampSeconds < currentTimestamp - _timestampToleranceSeconds || timestampSeconds > currentTimestamp + _timestampToleranceSeconds)
        {
            _logger.LogDebug("Rejected a Telnyx webhook timestamp outside the allowed tolerance");
            return false;
        }

        string publicKey;

        try
        {
            publicKey = await _publicKeysUtil.Get(cancellationToken).NoSync();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Unable to retrieve the Telnyx webhook-signing public key");
            return false;
        }

        string signedPayload = string.Concat(timestamp, "|", payload);
        bool valid = Ed25519Util.Verify(publicKey, signature, signedPayload);

        if (valid)
            return true;

        string refreshedPublicKey;

        try
        {
            refreshedPublicKey = await _publicKeysUtil.RefreshIfCurrent(publicKey, cancellationToken).NoSync();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Unable to refresh the Telnyx webhook-signing public key");
            return false;
        }

        if (string.Equals(publicKey, refreshedPublicKey, StringComparison.Ordinal))
        {
            _logger.LogDebug("Rejected an invalid Telnyx webhook signature");
            return false;
        }

        valid = Ed25519Util.Verify(refreshedPublicKey, signature, signedPayload);

        if (!valid)
            _logger.LogDebug("Rejected an invalid Telnyx webhook signature after refreshing the public key");

        return valid;
    }
}
