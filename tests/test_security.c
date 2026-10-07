#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "../base64.h"
#include "../hash.h"

int pbkdf2_check(char *password, char *hash);

static void test_base64_boundaries(void)
{
	unsigned char output[8] = {0};

	assert(base64_decode("TQ==", output, sizeof(output)) == 1);
	assert(output[0] == 'M');
	assert(base64_decode("TWE=", output, sizeof(output)) == 2);
	assert(memcmp(output, "Ma", 2) == 0);
	assert(base64_decode("TWFu", output, sizeof(output)) == 3);
	assert(memcmp(output, "Man", 3) == 0);
	assert(base64_decode("", output, sizeof(output)) == -1);
	assert(base64_decode("A", output, sizeof(output)) == -1);
	assert(base64_decode("AAA", output, sizeof(output)) == -1);
	assert(base64_decode("AAAAA", output, sizeof(output)) == -1);
	assert(base64_decode("AA=A", output, sizeof(output)) == -1);
	assert(base64_decode("====", output, sizeof(output)) == -1);
	assert(base64_decode("TWFu", output, 2) == -1);
}

static void test_pbkdf2_validation(void)
{
	char valid[] = "PBKDF2$sha256$1000$fixture-salt$nZ3EHCrwAqN1frClVMIzSaJ/OGAwlvSKqsa/ww/W1e4=";
	char *invalid[] = {
		"",
		"PBKDF2$sha256",
		"PBKDF2$md5$1000$salt$AAAA",
		"PBKDF2$sha256$0$salt$AAAA",
		"PBKDF2$sha256$-1$salt$AAAA",
		"PBKDF2$sha256$10000001$salt$AAAA",
		"PBKDF2$sha256$12x$salt$AAAA",
		"PBKDF2$sha256$1000$salt$A",
		"PBKDF2$sha256$1000$salt$AAAA$trailing",
		NULL
	};
	int i;

	assert(pbkdf2_check("local-only-password", valid) == 1);
	assert(pbkdf2_check("wrong", valid) == 0);
	for (i = 0; invalid[i] != NULL; i++)
		assert(pbkdf2_check("local-only-password", invalid[i]) == 0);
}

static void test_option_lifecycle(void)
{
	p_add("duplicate", "first");
	p_add("duplicate", "second");
	assert(strcmp(p_stab("duplicate"), "second") == 0);
	p_freeall();
	assert(p_stab("duplicate") == NULL);
}

int main(void)
{
	test_base64_boundaries();
	test_pbkdf2_validation();
	test_option_lifecycle();
	return 0;
}
