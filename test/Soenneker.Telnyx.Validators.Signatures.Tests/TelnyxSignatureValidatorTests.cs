using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Soenneker.Telnyx.PublicKeys.Abstract;
using Soenneker.Telnyx.Validators.Signatures.Abstract;
using Soenneker.Tests.HostedUnit;
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Telnyx.Validators.Signatures.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class TelnyxSignatureValidatorTests : HostedUnitTest
{
    private readonly ITelnyxSignatureValidator _util;

    public TelnyxSignatureValidatorTests(Host host) : base(host)
    {
        _util = Resolve<ITelnyxSignatureValidator>(true);
    }

    [Test]
    public async Task Default()
    {
        await Assert.That(_util).IsNotNull();
    }

    [Test]
    public async Task Validate_should_accept_a_current_valid_signature()
    {
        const string payload = "{\"data\":{\"id\":\"event-id\"}}";
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var privateKey = new Ed25519PrivateKeyParameters(CreatePrivateKeySeed(), 0);
        string publicKey = Convert.ToBase64String(privateKey.GeneratePublicKey().GetEncoded());
        string signature = Convert.ToBase64String(Sign(privateKey, $"{timestamp}|{payload}"));
        var publicKeys = new TestPublicKeysUtil(publicKey);
        var validator = new TelnyxSignatureValidator(publicKeys, NullLogger<TelnyxSignatureValidator>.Instance);

        bool valid = await validator.Validate(payload, signature, timestamp);

        await Assert.That(valid).IsTrue();
        await Assert.That(publicKeys.GetCount).IsEqualTo(1);
    }

    [Test]
    public async Task Validate_should_reject_a_tampered_payload()
    {
        const string payload = "{\"data\":{\"id\":\"event-id\"}}";
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var privateKey = new Ed25519PrivateKeyParameters(CreatePrivateKeySeed(), 0);
        string publicKey = Convert.ToBase64String(privateKey.GeneratePublicKey().GetEncoded());
        string signature = Convert.ToBase64String(Sign(privateKey, $"{timestamp}|{payload}"));
        var validator = new TelnyxSignatureValidator(new TestPublicKeysUtil(publicKey), NullLogger<TelnyxSignatureValidator>.Instance);

        bool valid = await validator.Validate($"{payload} ", signature, timestamp);

        await Assert.That(valid).IsFalse();
    }

    [Test]
    public async Task Validate_should_refresh_and_retry_after_key_rotation()
    {
        const string payload = "{\"data\":{\"id\":\"rotated-key\"}}";
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var oldPrivateKey = new Ed25519PrivateKeyParameters(new byte[32], 0);
        var newPrivateKey = new Ed25519PrivateKeyParameters(CreatePrivateKeySeed(), 0);
        string oldPublicKey = Convert.ToBase64String(oldPrivateKey.GeneratePublicKey().GetEncoded());
        string newPublicKey = Convert.ToBase64String(newPrivateKey.GeneratePublicKey().GetEncoded());
        string signature = Convert.ToBase64String(Sign(newPrivateKey, $"{timestamp}|{payload}"));
        var publicKeys = new TestPublicKeysUtil(oldPublicKey, newPublicKey);
        var validator = new TelnyxSignatureValidator(publicKeys, NullLogger<TelnyxSignatureValidator>.Instance);

        bool valid = await validator.Validate(payload, signature, timestamp);

        await Assert.That(valid).IsTrue();
        await Assert.That(publicKeys.RefreshCount).IsEqualTo(1);
    }

    [Test]
    public async Task Validate_should_accept_a_valid_signature_regardless_of_timestamp_age()
    {
        const string payload = "{}";
        string timestamp = DateTimeOffset.UtcNow.AddMinutes(-6).ToUnixTimeSeconds().ToString();
        var privateKey = new Ed25519PrivateKeyParameters(CreatePrivateKeySeed(), 0);
        string publicKey = Convert.ToBase64String(privateKey.GeneratePublicKey().GetEncoded());
        string signature = Convert.ToBase64String(Sign(privateKey, $"{timestamp}|{payload}"));
        var publicKeys = new TestPublicKeysUtil(publicKey);
        var validator = new TelnyxSignatureValidator(publicKeys, NullLogger<TelnyxSignatureValidator>.Instance);

        bool valid = await validator.Validate(payload, signature, timestamp);

        await Assert.That(valid).IsTrue();
        await Assert.That(publicKeys.GetCount).IsEqualTo(1);
    }

    [Test]
    public async Task Validate_should_reject_malformed_headers()
    {
        var publicKeys = new TestPublicKeysUtil(Convert.ToBase64String(new byte[32]));
        var validator = new TelnyxSignatureValidator(publicKeys, NullLogger<TelnyxSignatureValidator>.Instance);

        bool missingTimestamp = await validator.Validate("{}", Convert.ToBase64String(new byte[64]), "");
        bool invalidSignature = await validator.Validate("{}", "not-base64", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

        await Assert.That(missingTimestamp).IsFalse();
        await Assert.That(invalidSignature).IsFalse();
    }

    private static byte[] CreatePrivateKeySeed()
    {
        var seed = new byte[32];

        for (var index = 0; index < seed.Length; index++)
            seed[index] = checked((byte) (index + 1));

        return seed;
    }

    private static byte[] Sign(Ed25519PrivateKeyParameters privateKey, string message)
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, privateKey);
        signer.BlockUpdate(messageBytes, 0, messageBytes.Length);
        return signer.GenerateSignature();
    }

    private sealed class TestPublicKeysUtil : ITelnyxPublicKeysUtil
    {
        private string _publicKey;
        private readonly string _refreshedPublicKey;
        private int _getCount;
        private int _refreshCount;

        public int GetCount => _getCount;
        public int RefreshCount => _refreshCount;

        public TestPublicKeysUtil(string publicKey, string? refreshedPublicKey = null)
        {
            _publicKey = publicKey;
            _refreshedPublicKey = refreshedPublicKey ?? publicKey;
        }

        public ValueTask<string> Get(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _getCount);
            return new ValueTask<string>(_publicKey);
        }

        public ValueTask<string> Refresh(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _refreshCount);
            _publicKey = _refreshedPublicKey;
            return new ValueTask<string>(_publicKey);
        }

        public ValueTask<string> RefreshIfCurrent(string expectedPublicKey, CancellationToken cancellationToken = default)
        {
            if (!string.Equals(_publicKey, expectedPublicKey, StringComparison.Ordinal))
                return new ValueTask<string>(_publicKey);

            return Refresh(cancellationToken);
        }
    }
}
