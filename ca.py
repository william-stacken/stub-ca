import os
import sys
import time
import struct

PRIV_KEY_EXT = "key"
PUB_KEY_EXT = "pub"
CERT_EXT = "cert"
SERIAL_NUMBER_EXT = "serial"
SIGNATURE_EXT = "sig"

PCA_NAME = "pca"
PC_NAME = "pc"

PCA_VALID_DUR = 60 * 60 * 24 * 365 * 10 # 10 years
PC_VALID_DUR = 60 * 60 * 24 # 1 day

# Little endian with 8-byte serial number, 4-byte "valid after" timestamp, 4-byte "valid before" timestamp,
# and 2-byte public key size.
CERT_STRUCT_FORMAT = "<QIIH"

DIGEST_ALGO = "sha256"

key_size = 256

def sn_get(sn_file):	
	if os.path.exists(pca_cert):
		with open(sn_file, "r") as f:
			sn = int(f.read())
	else:
		sn = 0
		with open(sn_file, "w+") as f:
			f.write(str(sn))

	return sn;

def sn_update(sn_file):
	sn = sn_get(sn_file) + 1
	with open(sn_file, "w") as f:
		f.write(str(sn))

def make_cert(ec_name, cert, key, pca_key, sn, valid_after, valid_before, sig):
	"""Create a certificate and sign it using SHA256

	Parameters
	----------
		ec_name: str
			The eliptic curve to use when generating the key pair.
		cert: str
			Path to where the certificate should be written.
		key: str
			Path to where the private key should be written.
		pca_key: str
			Path to CA private key used to sign the certificate.
		sn: int
			The serial number of the certificate to be written.
		valid_after: int
			The valid after field of the certificate to be written.
		valid_before: int
			The valid before field of the certificate to be written.
		cert_sig: str
			Temporary path to where the signature should be written.
	"""
	os.system("openssl ecparam -name %s -genkey -noout -outform DER -out \"%s\"" % (ec_name, key))
	os.system("openssl ec -in \"%s\" -inform DER -pubout -outform DER -out \"%s\"" % (key, cert))

	with open(cert, "rb") as f:
		pub = f.read()

	cert_tbs = struct.pack(CERT_STRUCT_FORMAT, sn, valid_after, valid_before, len(pub)) + pub
	with open(cert, "wb+") as f:
		f.write(cert_tbs)

	# Create signature
	os.system("openssl dgst -sign \"%s\" -keyform DER -%s -out \"%s\" -binary \"%s\"" % (pca_key, DIGEST_ALGO, cert_sig, cert))

	with open(cert_sig, "rb") as f:
		sig = f.read()

	with open(cert, "wb+") as f:
		f.write(cert_tbs)
		f.write(sig)

	#os.remove(cert_sig)


def get_cert(cert):
	with open(cert, "rb") as f:
		raw = f.read()
	str_size = struct.calcsize(CERT_STRUCT_FORMAT)
	if len(raw) <= str_size:
		print("Could not decode certificate %s, must have a size greater than %d bytes" % (cert, str_size))
		sys.exit(1)

	(sn, valid_after, valid_before, pk_size) = struct.unpack(CERT_STRUCT_FORMAT, raw[:str_size])
	if len(raw) <= str_size + pk_size:
		print("Could not decode certificate %s, must have a size greater than %d + %d bytes" % (cert, str_size, pk_size))
		sys.exit(1)
	pub = raw[str_size:str_size + pk_size]
	sig = raw[str_size + pk_size:]

	return (sn, valid_after, valid_before, pub, sig)

def verify_cert(cert, pca_cert, cert_sig, pca_pub_key):
	"""Verify that a certificate is valid and signed by the given CA

	Parameters
	----------
		cert: str
			Path to the certificate to verify.
		pca_cert: str
			Path to the CA certificate used for verification.
		cert_tbs: str
			Path to temporarily store the certificate's extracted to-be-signed fields.
		cert_sig: str
			Path to temporarily store the certificate's extracted signature.
		pca_pub_key: str
			Path to temporarily store the CA certificate's extracted public key.
	"""
	now = int(time.time())
	(sn, valid_after, valid_before, pca, sig) = get_cert(cert)

	if now < valid_after or now >= valid_before:
		raise Exception("Ceritifcate %s is not valid yet or has expired" % cert)

	with open(cert_tbs, "wb+") as f:
		f.write(struct.pack(CERT_STRUCT_FORMAT, sn, valid_after, valid_before, len(pub)))
		f.write(pub)

	with open(cert_sig, "wb+") as f:
		f.write(sig)

	(sn, valid_after, valid_before, pca_pub, pca_sig) = get_cert(pca_cert)

	if now < valid_after or now >= valid_before:
		raise Exception("CA ceritifcate %s is not valid yet or has expired" % pca_cert)

	with open(pca_pub_key, "wb+") as f:
		f.write(pca_pub)

	os.system("openssl dgst -verify \"%s\" -keyform DER -%s -signature \"%s\" -binary \"%s\"" % (pca_pub_key, DIGEST_ALGO, sig, cert_tbs))

	#os.remove(cert_tbs)
	#os.remove(cert_sig)
	#os.remove(pca_pub_key)



if len(sys.argv) >= 2:
	if sys.argv[1] != "256" and sys.argv[1] != "384" and sys.argv[1] != "512":
		print("Unknown key size '%s', must be one of 256, 384, or 512." % sys.argv[1])
		sys.exit(1)

	key_size = int(sys.argv[1])

ec = "secp%dr1" % key_size

pca_cert = "%s-%d.%s" % (PCA_NAME, key_size, CERT_EXT)
pca_pub_key = "%s-%d.%s" % (PCA_NAME, key_size, PUB_KEY_EXT)
pca_priv_key = "%s-%d.%s" % (PCA_NAME, key_size, PRIV_KEY_EXT)
pca_sn = "%s-%d.%s" % (PCA_NAME, key_size, SERIAL_NUMBER_EXT)

epoch_now = int(time.time())
sn = 0

# Create PCA if it does not exist
if not os.path.exists(pca_cert) and not os.path.exists(pca_priv_key) and not os.path.exists(pca_sn):
	sn = sn_get(pca_sn)
	valid_after = epoch_now
	valid_before = valid_after + PCA_VALID_DUR
	make_cert(ec, pca_cert, pca_priv_key, sn, valid_after, valid_before)
# Open PCA if it exists
elif os.path.exists(pca_cert) and os.path.exists(pca_priv_key) and os.path.exists(pca_sn):
	(sn, valid_after, valid_before, pca_pub) = get_cert(pca_cert)
	sn = sn_get(pca_sn)
else:
	print("Could not update PCA due to one of %s, %s, or %s not being present" % (pca_cert, pca_priv_key, pca_sn))
	sys.exit(1)

sn += 1
valid_after = epoch_now
valid_before = valid_after + PC_VALID_DUR
pseudo_cert = "%s-%d-%08x.%s" % (PC_NAME, key_size, sn, CERT_EXT)
pseudo_signature = "%s-%d-%08x.%s" % (PC_NAME, key_size, sn, SIGNATURE_EXT)
pseudo_priv_key = "%s-%d-%08x.%s" % (PC_NAME, key_size, sn, PRIV_KEY_EXT)

make_cert(ec, pseudo_cert, pseudo_priv_key, sn, valid_after, valid_before)
sign_cert(pseudo_cert, pseudo_signature, pca_cert, pca_priv_key, pca_pub_key)
sn_update(pca_sn)

