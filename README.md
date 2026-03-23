# WARPS

This is a DLL that modifies the Cloudflare WARP client to use a custom SNI.

## How it works

DLL side-loaded into `warp-svc.exe`. Scans the `.rdata` section at runtime for strings, walks the `.text` segment, and patches `LEA` pointer instructions. Hooks Winsock APIs, extracts datagrams, recalculates framing, and re-encrypts. Should work after WARP updates.

## Usage

Download the latest release and run `install.bat`.