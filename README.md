[![](https://img.shields.io/nuget/v/soenneker.telnyx.validators.signatures.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.telnyx.validators.signatures/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.telnyx.validators.signatures/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.telnyx.validators.signatures/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.telnyx.validators.signatures.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.telnyx.validators.signatures/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Telnyx.Validators.Signatures
### Ed25519 signature validation for Telnyx webhooks

## Installation

```bash
dotnet add package Soenneker.Telnyx.Validators.Signatures
```

## Registration

```csharp
using Soenneker.Telnyx.Validators.Signatures.Registrars;

services.AddTelnyxSignatureValidatorAsSingleton();
```

Configure the Telnyx API token used to retrieve the account's webhook-signing public key:

```json
{
  "Telnyx": {
    "Token": "KEY..."
  }
}
```

## Usage

Pass the raw request body and the two Telnyx signature headers to the validator:

```csharp
string payload = await reader.ReadToEndAsync(cancellationToken);
string signature = request.Headers["telnyx-signature-ed25519"].ToString();
string timestamp = request.Headers["telnyx-timestamp"].ToString();

bool valid = await validator.Validate(payload, signature, timestamp, cancellationToken);
```

The request body must be validated before it is parsed and reserialized. Telnyx signs the exact
`{timestamp}|{payload}` content. The timestamp is included in signature verification but is not checked for freshness.

If verification fails, the validator conditionally refreshes the cached public key and retries once. Conditional refreshes
are single-flight and rate-limited so invalid traffic cannot cause an unbounded number of Telnyx API requests.
