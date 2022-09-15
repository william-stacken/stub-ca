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

# Little endian with 8-byte serial number, 4-byte "valid after" timestamp, and 4-byte "valid before" timestamp
CERT_STRUCT_FORMAT = "<QII"

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

def make_cert(ec_name, cert, key, sn, valid_after, valid_before):
	os.system("openssl ecparam -name %s -genkey -noout -outform DER -out \"%s\"" % (ec_name, key))
	os.system("openssl ec -in \"%s\" -inform DER -pubout -outform DER -out \"%s\"" % (key, cert))

	with open(cert, "rb") as f:
		pub = f.read()

	with open(cert, "wb+") as f:
		f.write(struct.pack(CERT_STRUCT_FORMAT, sn, valid_after, valid_before))
		f.write(pub)

def get_cert(cert):
	with open(cert, "rb") as f:
		raw = f.read()
	str_size = struct.calcsize(CERT_STRUCT_FORMAT)
	if len(raw) <= str_size:
		print("Could not decode certificate %s, must have at least a size of %d bytes" % (cert, str_size))
		sys.exit(1)

	(sn, valid_after, valid_before) = struct.unpack(CERT_STRUCT_FORMAT, raw[:str_size])
	pub = raw[str_size:]
	if epoch_now < valid_after or epoch_now >= valid_before:
		print("Ceritifcate %s is not valid yet or has expired" % cert)
		sys.exit(1)

	return (sn, valid_after, valid_before, pub)

def sign_cert(cert, sig, pca_cert, pca_key, pca_pub_key):
	# Create signature
	os.system("openssl dgst -sign \"%s\" -keyform DER -%s -out \"%s\" -binary \"%s\"" % (pca_key, DIGEST_ALGO, sig, cert))

	# Verify signature
	(sn, valid_after, valid_before, pca_pub) = get_cert(pca_cert)

	with open(pca_pub_key, "wb+") as f:
		f.write(pca_pub)

	os.system("openssl dgst -verify \"%s\" -keyform DER -%s -signature \"%s\" -binary \"%s\"" % (pca_pub_key, DIGEST_ALGO, sig, cert))


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

