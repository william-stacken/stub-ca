# Stub-CA
A simple stub certificate authority using python and openssl.

The certificates uses the following custom format (not X.509):
- Serial number (8 octets)
- Valid After (4 octets, unix epoch)
- Valid Before (4 octets, unix epoch)
- Public key Size (2 octets, bytes)
- Public key (Variable Size, DER encoded)
- Signature (Variable Size, DER encoded)

All fields that do not have a variable size are little-endian encoded, and all fields except
for the Signature are signed and are refered to as TBS (to-be-signed). The size of the Signature
is defined as the size of the entire certificate subtracted by the size of the TBS.
Note that revocation is not supported by this CA.

Usage:
`python3 ca.py [bit-size] [command] [args]`
where `[bit-size]` is either 256, 384, or 512 and `[command]` is one of the following:
- `create`: Creates a CA certificate if it does not already exist, and issues a new certificate with the next serial number.
- `show [cert-path]`: Decodes and prints the certificate at `[cert-path]` to stdout.

The `secp[bit-size]r1` curve is used to generate public and private keys
and signatures are generated using SHA256.

The `create` command will generate the following CA files (if not already present)
- `pca-[bit-size].cert`: The CA certificate with Valid After set to the current time and
                         Valid Before set to 10 years into the future.
- `pca-[bit-size].key`: The CA private key in plain DER encoding.
- `pca-[bit-size].serial`: Contains the serial number to use for the next issued certificate.
                           Initialized to zero.

It will also generate a single certificate issued by the CA:
- `pc-[bit-size]-[serial-no].cert`: The certificate signed by the CA with Valid After set
                                    to the current time and Valid Before set to 1 day into
                                    the future.
- `pc-[bit-size]-[serial-no].key`: The certificate's private key in plain DER encoding.
