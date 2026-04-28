# Changelog

## [1.0.3]

### Fixed

- **`VaultHttp.PostAsync`: JSON double-encoding caused HTTP 400 from Vault/OpenBao**

  `PostAsync` manually serialized the request body to a JSON string using `JsonSerializer.Serialize`, then passed that string to `request.AddJsonBody()`. In RestSharp ≥ 106, `AddJsonBody` re-serializes whatever object it receives — when the argument is a `string`, it encodes it as a JSON string literal, wrapping the content in quotes and escaping the inner characters. Vault/OpenBao received `"{\\"csr\\":\\"...\\"}"` (a JSON-encoded string) instead of `{"csr":"..."}` (a JSON object) and returned HTTP 400 "error parsing JSON".

  Fixed by replacing `request.AddJsonBody(serializedParams)` with `request.AddStringBody(serializedParams, ContentType.Json)`. `AddStringBody` sends the string as the raw request body without re-encoding it.

- **`ThrowOnAnyError = true` made the `BadRequest` error-parsing block dead code**

  `RestClientOptions` was constructed with `ThrowOnAnyError = true`, which causes RestSharp to throw an exception on any non-2xx response before returning to the caller. The `PostAsync` method had explicit handling for `HttpStatusCode.BadRequest` that deserialized Vault error messages and threw a descriptive exception — but that block was never reached because RestSharp threw first, and the actual Vault error body was lost.

  Fixed by removing `ThrowOnAnyError = true` from `RestClientOptions` and adding `response.ThrowIfError()` after the explicit `BadRequest` handler, so non-2xx responses that are not `BadRequest` still surface as exceptions while `BadRequest` responses are handled with full Vault error body parsing.

- **`ValidateCAConnectionInfo` and `ValidateProductInfo`: `KeyNotFoundException` on gateway config PUT/POST**

  Both validation methods used direct `Dictionary.get_Item` indexers (`connectionInfo[key]`) to read parameters. The gateway does not always pre-populate every parameter key before calling validation, so any absent key threw `KeyNotFoundException` and surfaced as an opaque HTTP 500 from the gateway config endpoint.

  Fixed by replacing all direct indexers with `TryGetValue` calls throughout both methods.

  Additionally relaxed the `RoleName` requirement in `ValidateProductInfo`: the `Enroll` path already falls back to `ProductID` when `RoleName` is absent, so the validator no longer rejects configurations that omit it. The check now only errors if `RoleName` is explicitly present but empty.

### Changed

- Dropped .NET 6.0 target (EOL). The project now targets `net8.0` and `net10.0`.
