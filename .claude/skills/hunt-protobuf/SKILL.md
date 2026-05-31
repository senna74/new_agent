---
name: hunt-protobuf
description: "Use this skill when you see base64-encoded binary data in requests, when a request body or query parameter does not decode to readable JSON, when the Content-Type is application/x-protobuf / application/grpc / application/grpc-web, when parameter names look like 'data' / 'payload' / 'proto' / 'pb' / 'grpcrequest', or when fingerprint indicates Google-stack / gRPC backend. Protobuf is binary serialization that most hunters skip — that means uncontested IDORs, BAC, mass-assignment, and privilege-flag manipulation hide inside protobuf fields. Only invoke this skill if there is real impact potential. Skip theoretical findings."
type: hunt
---

# Hunt: Protobuf / gRPC

## What is Protobuf
Binary serialization format used by Google and many large apps. Often appears as base64-encoded blobs in HTTP parameters, request bodies, or gRPC-Web envelopes. Most hunters skip these because the data looks opaque — that's the opportunity.

## How to Identify
- Base64 blob in a parameter or body that does not decode to readable JSON/text
- `Content-Type: application/x-protobuf`, `application/grpc`, `application/grpc-web`, `application/grpc-web+proto`, `application/grpc-web-text`
- Parameter / field names: `data`, `payload`, `proto`, `pb`, `grpcrequest`, `body`, `req`, `request`
- Response headers like `grpc-status`, `grpc-message`, `grpc-accept-encoding`
- URL paths containing `/twirp/`, `/grpc/`, `/api.<Service>/<Method>`
- JS bundles with `protobuf-ts`, `google-protobuf`, `connect-rpc`, `grpc-web` imports
- Frontend code with `.fromBinary(...)`, `.toBinary(...)`, `Reader`, `Writer` invocations

## Triage Triggers
- App is Google-stack (Firebase, Google Cloud, Pub/Sub, AdSense, Workspace) → very likely protobuf
- App uses Connect-Web / tRPC-on-Connect / grpc-web → definitely protobuf
- Mobile (Android) app — APK frequently uses protobuf for backend calls; decompile with `jadx` and look for `.proto` resources / `Builder` classes

## Attack Steps

1. **Decode**
   ```bash
   echo "<blob>" | base64 -d | xxd | head
   ```
   Look for wire-format pattern: `<tag/wire-type byte> <varint or length-prefix> <value>`.

2. **Parse without schema (blackbox)**
   ```bash
   echo "<blob>" | base64 -d | protoc --decode_raw
   ```
   `--decode_raw` does not need a `.proto` file — it gives you field-number → value mappings.

3. **Identify field types from values**
   - Tag byte: low 3 bits = wire type, high bits = field number
   - Wire types: 0=varint (ints/bools/enums), 1=64-bit (double/fixed64), 2=length-delimited (string/bytes/embedded message), 5=32-bit (float/fixed32)
   - Look for: user IDs (varint), resource IDs (varint or string), role values (enum/varint), permission flags (varint bools)

4. **Modify and re-encode**
   - Change varint values for IDs / role flags (try 0, 1, MAXINT, your-victim-ID)
   - Toggle boolean flags (`is_admin`, `verified`, `paid_tier`)
   - Inject SQLi / SSRF / path-traversal payloads into string fields
   - Add unknown field numbers — server-side parsers often accept and ignore them, but some pass them to downstream services that DO honor them (mass assignment via protobuf)

5. **Test attack classes**
   - **IDOR:** swap target ID field with a victim's ID
   - **BAC / privesc:** flip `role`, `is_admin`, `permissions[]` enum values
   - **Mass assignment:** add field numbers the client never sends (e.g., field 99 = `is_admin: true`)
   - **Type confusion:** send a string where the server expects an int; some parsers crash or accept it
   - **Length-delimited overflow:** send extremely large length prefix
   - **Injection:** SQLi / SSRF / cmdi in string fields (especially user-controlled ones)

6. **Encode and replay**
   - Re-encode with `protoc --encode` (if you have the schema) or with a quick Python script using `google.protobuf` raw decode/encode
   - For gRPC-Web: wrap in the frame format — 1 byte flag + 4 bytes length + payload

## gRPC-Web Frame Format

```
| 1 byte flag | 4 bytes big-endian length | <protobuf payload> |
```
- flag = 0x00 → data frame
- flag = 0x80 → trailer frame
- Re-frame before sending; servers reject malformed frames silently

## Recommended Tools

- `protoc --decode_raw` — schemaless parse
- `protobuf-inspector` — pretty-printer
- `blackboxprotobuf` (Burp Suite extension) — auto-decode/re-encode in repeater
- `grpcurl` — speak gRPC from CLI with reflection if enabled (`grpcurl -plaintext <host>:443 list`)
- `evans` — interactive gRPC client

## Schema Recovery

If schema is not exposed:
1. Check for gRPC reflection: `grpcurl -plaintext <host> list` then `describe <Service>`
2. Decompile mobile APK with jadx; look for `*Proto.java`, `*OuterClass.java`, `descriptor.proto` resources
3. JS bundle: search for `.proto` strings, `fromJSON`, `toJSON`, `fromBinary` definitions — modern protobuf-ts emits readable JS schemas
4. `--decode_raw` field numbers + observed string values often let you reconstruct enough of the schema to attack

## Why This Works
- Most hunters ignore protobuf → less competition
- Contains IDs and values not visible in normal JSON
- Server-side validation often trusts the client (because "binary protocol = our app only")
- Google programs pay very well for protobuf-based IDORs

## Claude Prompt Template

> "Here is a base64-encoded protobuf blob: `<BLOB>`
> Parse the structure with `protoc --decode_raw`, identify all fields and values, then help me test each field for IDOR / mass assignment / authorization bypass. Re-encode after each modification."

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
