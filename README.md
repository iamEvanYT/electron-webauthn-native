# electron-webauthn

A high-performance, cross-platform WebAuthn/Passkey implementation for Electron applications, built with Rust and native platform APIs.

## Overview

This library provides seamless WebAuthn (Web Authentication) and Passkey support for Electron applications across multiple platforms. It leverages native platform authenticators including Touch ID, Face ID, Windows Hello, and security keys to deliver a secure and user-friendly authentication experience.

### Key Features

- **Native Platform Integration**: Uses platform-specific APIs for optimal performance and security
- **Cross-Platform Support**: Works on macOS, Windows, and Linux
- **WebAuthn Level 2 Compliance**: Full support for the latest WebAuthn specifications
- **Biometric Authentication**: Touch ID, Face ID, Windows Hello, and Apple Watch support
- **Secure Enclave Integration**: Hardware-backed key storage on supported platforms
- **TypeScript Support**: Complete type definitions included

## Requirements

### macOS

- **macOS 13+ (Ventura or later)** - Required for ASAuthorization framework
- Touch ID, Face ID, or Apple Watch for biometric authentication
- Valid code signing certificate for production use

### Windows

- **Windows 10 version 1903+ or Windows 11**
- Windows Hello capable device (fingerprint, face recognition, or PIN)

### Linux

- Modern Linux distribution with WebAuthn support
- Compatible authenticator device

## Installation

```bash
npm install electron-webauthn
# or
yarn add electron-webauthn
```

## Usage

### Basic Registration (Creating a Credential)

```typescript
import { createCredential } from "electron-webauthn";

const options = {
  rp: {
    id: "example.com",
    name: "Example Corp",
  },
  user: {
    id: new Uint8Array([1, 2, 3, 4]),
    name: "user@example.com",
    displayName: "John Doe",
  },
  challenge: new Uint8Array(32), // Generate random 32 bytes
  pubKeyCredParams: [
    { type: "public-key", alg: -7 }, // ES256
    { type: "public-key", alg: -257 }, // RS256
  ],
  authenticatorSelection: {
    authenticatorAttachment: "platform",
    userVerification: "required",
  },
};

try {
  const credential = await createCredential(options);
  console.log("Registration successful:", credential);
} catch (error) {
  console.error("Registration failed:", error);
}
```

### Basic Authentication (Getting a Credential)

```typescript
import { getCredential } from "electron-webauthn";

const options = {
  rpId: "example.com",
  challenge: new Uint8Array(32), // Generate random 32 bytes
  allowCredentials: [
    {
      type: "public-key",
      id: credentialId, // From previous registration
    },
  ],
  userVerification: "required",
};

try {
  const assertion = await getCredential(options);
  console.log("Authentication successful:", assertion);
} catch (error) {
  console.error("Authentication failed:", error);
}
```

## Platform Support

| Platform | Architecture  | Status | Notes                          |
| -------- | ------------- | ------ | ------------------------------ |
| macOS    | arm64         | ✅     | Native ASAuthorization support |
| macOS    | x64           | ✅     | Native ASAuthorization support |
| macOS    | universal     | ✅     | Universal binary               |
| Windows  | x64           | ✅     | Windows Hello integration      |
| Windows  | arm64         | ✅     | Windows Hello integration      |
| Windows  | ia32          | ✅     | Windows Hello integration      |
| Linux    | x64 (GNU)     | ✅     | Generic WebAuthn support       |
| Linux    | x64 (musl)    | ✅     | Alpine Linux compatible        |
| Linux    | arm64 (GNU)   | ✅     | ARM64 Linux support            |
| Linux    | arm64 (musl)  | ✅     | ARM64 Alpine support           |
| Linux    | riscv64 (GNU) | ✅     | RISC-V architecture            |

## macOS Entitlements

For macOS applications, you need to include the following entitlements in your `entitlements.plist` file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Required for WebAuthn/Passkey support -->
    <key>com.apple.developer.authentication-services.autofill-credential-provider</key>
    <true/>

    <!-- Required for platform authenticator access -->
    <key>com.apple.developer.web-browser</key>
    <true/>

    <!-- Required for Touch ID/Face ID/Apple Watch access -->
    <key>com.apple.security.device.biometry</key>
    <true/>

    <!-- Required for keychain access -->
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.yourcompany.yourapp</string>
    </array>

    <!-- Optional: For network requests to verify credentials -->
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
```

### Electron Builder Configuration

If using `electron-builder`, add the entitlements to your `package.json`:

```json
{
  "build": {
    "mac": {
      "entitlements": "build/entitlements.mac.plist",
      "entitlementsInherit": "build/entitlements.mac.plist",
      "hardenedRuntime": true
    }
  }
}
```

## Development

### Prerequisites

- Node.js 16+
- Rust 1.70+
- Platform-specific build tools:
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools
  - **Linux**: build-essential

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/electron-webauthn.git
cd electron-webauthn

# Install dependencies
npm install

# Build the native module
npm run build

# Run tests
npm test
```

### Architecture

This library uses:

- **Rust** for high-performance native implementations
- **NAPI-RS** for seamless Node.js bindings
- **Platform-specific APIs**:
  - macOS: ASAuthorization framework
  - Windows: Windows Hello APIs
  - Linux: Generic WebAuthn implementation

## Error Handling

The library provides detailed error messages for common scenarios:

```typescript
try {
  const credential = await createCredential(options);
} catch (error) {
  switch (error.code) {
    case "NotSupportedError":
      console.log("WebAuthn not supported on this platform");
      break;
    case "SecurityError":
      console.log("Security requirements not met");
      break;
    case "NotAllowedError":
      console.log("User cancelled or timeout occurred");
      break;
    default:
      console.log("Unexpected error:", error.message);
  }
}
```

## Security Considerations

- Always validate challenges on your server
- Use HTTPS in production environments
- Implement proper CORS policies
- Store credentials securely on your backend
- Regularly update the library for security patches

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/electron-webauthn/issues)
- **Documentation**: [API Documentation](https://docs.your-org.com/electron-webauthn)
- **Community**: [Discussions](https://github.com/your-org/electron-webauthn/discussions)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.
