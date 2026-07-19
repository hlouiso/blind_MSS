# Vendored BLAKE3 C implementation

These files are copied without modification from the official BLAKE3 release
`1.8.5`, commit `93a431c78a52d7ccf0f366f106467f5070e6075e`:

<https://github.com/BLAKE3-team/BLAKE3>

The build selects NEON on ARM64, runtime-dispatched SSE2/SSE4.1/AVX2/AVX-512
on x86-64, and the portable implementation elsewhere. `LICENSE_CC0` is the
upstream CC0-1.0 license supplied with the release.
