# Stub-CA
A simple stub certificate authority using python and openssl.

The certificates uses the following custom format (not X.509):
- Serial number (8 octets)
- Valid After (4 octets, unix epoch)
- Valid Before (4 octets, unix epoch)
- Public key (Variable Length, DER encoded)

All fields except for the Public key are little-endian encoded. The certificate signature
is stored in a separate file. Also, revocation is not supported.

Usage:
`python3 ca.py [bit-size]`
where `[bit-size]` is either 256, 384, or 512.

The `secp[bit-size]r1` curve is used to generate public and private keys
and signatures are generated using SHA256.

This will generate the following CA files (if not already present)
- `pca-[bit-size].cert`: The CA certificate with Valid After set to the current time and
                         Valid Before set to 10 years into the future.
- `pca-[bit-size].key`: The CA private key in plain DER encoding.
- `pca-[bit-size].pub`: The CA public key (same as in the certificate, generated for debug purposes)
- `pca-[bit-size].serial`: Contains the serial number to use for the next issued certificate.
                           Initialized to zero.

It will also generate a single certificate issued by the CA:
- `pc-[bit-size]-[serial-no].cert`: The certificate with Valid After set to the current time and
                                    Valid Before set to 1 day into the future.
- `pc-[bit-size]-[serial-no].key`: The certificate's private key in plain DER encoding.
- `pc-[bit-size]-[serial-no].sig`: The certificate's signature produced by the CA's private key.
