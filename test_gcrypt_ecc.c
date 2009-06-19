
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <gcrypt.h>
#include <glib.h>

#define DEFAULT_DATA "This message will be signed\n"
#define DEFAULT_SIG "$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq"


void __init()
{
	gcry_error_t err;
	err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	if (gcry_err_code(err))
		fprintf(stderr, "Cannot enable libgcrypt's secure memory management\n");
	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void __test_keygen()
{
	__init();
	gcry_error_t err;
	
	gcry_sexp_t spec, key_pair, list;
	gcry_mpi_t pub, priv;

	err = gcry_sexp_build(&spec, NULL, "(genkey (ECDSA (nbits %d)))", 256);
	if (err) {
		fprintf(stderr, "gcry_sexp_new() failed with: %s\n", gcry_strerror(err));
		abort();
	}

	err = gcry_pk_genkey(&key_pair, spec);
	if (err) {
		fprintf(stderr, "gcry_pk_genkey() failed with: %s\n", gcry_strerror(err));
		abort();
	}

	list = gcry_sexp_find_token(key_pair, "q", 1);
	pub = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release (list);

	list = gcry_sexp_find_token(key_pair, "d", 1);
	priv = gcry_sexp_nth_mpi(list, 1, GCRYMPI_FMT_USG);

	gcry_sexp_release(list);
	gcry_sexp_release (key_pair);
	gcry_sexp_release (spec);

	unsigned char *pubkey;
	size_t publen, privlen;
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pubkey, &publen, pub);
	fprintf(stderr, "PUB: (%d) %s %p\n", (int)publen, pubkey, pubkey);

	unsigned char *privkey;
	gcry_mpi_aprint(GCRYMPI_FMT_HEX, &privkey, &privlen, priv);
	fprintf(stderr, "PRIV: (%d) %s %p\n", (int)privlen, privkey, privkey);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/test/ecc_keygen", __test_keygen);

	return g_test_run();
}
