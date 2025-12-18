![IDA-Fusion Logo](https://user-images.githubusercontent.com/89423559/170590973-86a0c0dd-2052-49a6-bf03-b2178754c3f6.png)

# IDA-Fusion

A fast and reliable signature scanner and creator plugin for IDA Pro 9.0+.

## Features

- **Fast & Reliable**: Optimized algorithms for efficient signature creation and scanning
- **Multiple Signature Formats**: Supports CODE style (`\x48\x89`), IDA style (`48 89 ? ?`), CRC-32, and FNV-1a hashes
- **Smart Wildcarding**: Automatically wildcards immediate values (IMM) in operands, focusing on opcodes only
- **Robust Signatures**: Effective against binaries with duplicated code sections
- **User-Friendly**: Auto-jumps to matches, clipboard integration, and streamlined workflow

## How It Works

IDA-Fusion creates signatures by wildcarding any operand containing an **immediate value (IMM)**. For example:

```
lea rax, [rbx+10h]  →  lea rax, [rbx+?]
```

This approach captures only the **opcodes**, making signatures more robust and reliable, especially for binaries designed to resist signature creation.

![Signature Creation Example](https://user-images.githubusercontent.com/89423559/170587870-133ff3c1-e95a-4a20-a9ca-deb1390cbd40.png)

_The highlighted portion shows what is omitted when creating a signature._

## Installation

### Pre-built Binaries

1. Download the latest [release](https://github.com/coconutbird/IDA-Fusion/releases)
2. Copy `IDA_Fusion32.dll` and `IDA_Fusion64.dll` to your IDA `plugins` folder
3. Access via `Edit > Plugins > Fusion` or press `Ctrl+Alt+S`

### Building from Source

**Requirements:**

- CMake 3.20+
- C++20 compatible compiler (MSVC, GCC, or Clang)
- IDA SDK (automatically downloaded if not present)

**Build Steps:**

```bash
# Configure and build for x64
cmake --preset x64-release
cmake --build --preset x64-release

# Configure and build for x86
cmake --preset x86-release
cmake --build --preset x86-release
```

The compiled plugins will be in `build/x64-release/` and `build/x86-release/` respectively.

**Manual SDK Setup (Optional):**

If you prefer to provide your own IDA SDK, extract it to a `sdk` folder in the project root.

## Usage

1. Select the code you want to create a signature for
2. Press `Ctrl+Alt+S` or use `Edit > Plugins > Fusion`
3. Choose your desired signature format
4. The signature is automatically copied to your clipboard

## Roadmap

- [ ] Reverse searching for smaller signatures
- [ ] Reference-based signature generation
- [ ] Additional signature optimization techniques

## Contributing

Contributions are welcome! Whether it's bug fixes, new features, or suggestions, feel free to open an issue or submit a pull request.

## Acknowledgments

This project is based on the original [IDA-Fusion](https://github.com/senator715/IDA-Fusion) by senator715, which appears to be no longer maintained. This fork modernizes the build system with CMake and updates to IDA SDK 9.0+.

**Note:** The original project supported IDA 7.5+. This fork requires IDA Pro 9.0+ due to the use of the modern IDA SDK from GitHub.

## License

See [LICENSE](LICENSE) for details.
