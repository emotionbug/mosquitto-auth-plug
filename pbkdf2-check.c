/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of mosquitto nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "base64.h"

#define SEPARATOR "$"
#define MAX_HASH_LENGTH 8192
#define MAX_ITERATIONS 10000000L
#define MAX_SALT_LENGTH 1024
#define MAX_DERIVED_KEY_LENGTH 1024

static int parse_iterations(const char *value, int *iterations)
{
	char *end = NULL;
	long parsed;

	if (value == NULL || *value == '\0')
		return -1;
	errno = 0;
	parsed = strtol(value, &end, 10);
	if (errno != 0 || *end != '\0' || parsed < 1 || parsed > MAX_ITERATIONS || parsed > INT_MAX)
		return -1;
	*iterations = (int)parsed;
	return 0;
}

static int detoken(const char *pbkstr, char **sha, int *iter, char **salt, char **key)
{
	char *p, *s, *save = NULL;
	int rc = -1;

	*sha = NULL;
	*salt = NULL;
	*key = NULL;
	if (pbkstr == NULL || strnlen(pbkstr, MAX_HASH_LENGTH + 1) > MAX_HASH_LENGTH)
		return -1;

	save = s = strdup(pbkstr);
	if (save == NULL)
		return -1;

#if defined(SUPPORT_DJANGO_HASHERS)
	if ((p = strsep(&s, "_")) == NULL || strcmp(p, "pbkdf2") != 0)
		goto out;
#else
	if ((p = strsep(&s, SEPARATOR)) == NULL || strcmp(p, "PBKDF2") != 0)
		goto out;
#endif

	if ((p = strsep(&s, SEPARATOR)) == NULL ||
	    (strcmp(p, "sha1") != 0 && strcmp(p, "sha256") != 0 && strcmp(p, "sha512") != 0))
		goto out;
	*sha = strdup(p);

	if ((p = strsep(&s, SEPARATOR)) == NULL || parse_iterations(p, iter) != 0)
		goto out;
	if ((p = strsep(&s, SEPARATOR)) == NULL || strlen(p) > MAX_SALT_LENGTH)
		goto out;
	*salt = strdup(p);
	if ((p = strsep(&s, SEPARATOR)) == NULL || *p == '\0' || s != NULL)
		goto out;
	*key = strdup(p);

	if (*sha == NULL || *salt == NULL || *key == NULL)
		goto out;
	rc = 0;

out:
	if (rc != 0) {
		free(*sha);
		free(*salt);
		free(*key);
		*sha = *salt = *key = NULL;
	}
	free(save);
	return rc;
}

int pbkdf2_check(char *password, char *hash)
{
	char *sha = NULL, *salt = NULL, *encoded = NULL;
	unsigned char *expected = NULL, *derived = NULL, *raw_salt = NULL;
	const unsigned char *salt_data;
	const EVP_MD *digest = NULL;
	int iterations = 0, expected_len, salt_len, match = 0;
	size_t encoded_len;

	if (password == NULL || detoken(hash, &sha, &iterations, &salt, &encoded) != 0)
		goto out;

	if (strcmp(sha, "sha1") == 0)
		digest = EVP_sha1();
	else if (strcmp(sha, "sha256") == 0)
		digest = EVP_sha256();
	else if (strcmp(sha, "sha512") == 0)
		digest = EVP_sha512();
	if (digest == NULL)
		goto out;

	encoded_len = strlen(encoded);
	expected = malloc(encoded_len);
	if (expected == NULL)
		goto out;
	expected_len = base64_decode(encoded, expected, encoded_len);
	if (expected_len < 1 || expected_len > MAX_DERIVED_KEY_LENGTH)
		goto out;

#ifdef RAW_SALT
	raw_salt = malloc(strlen(salt));
	if (raw_salt == NULL)
		goto out;
	salt_len = base64_decode(salt, raw_salt, strlen(salt));
	if (salt_len < 1 || salt_len > MAX_SALT_LENGTH)
		goto out;
	salt_data = raw_salt;
#else
	salt_len = (int)strlen(salt);
	if (salt_len < 1)
		goto out;
	salt_data = (const unsigned char *)salt;
#endif

	derived = malloc((size_t)expected_len);
	if (derived == NULL)
		goto out;
	if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt_data, salt_len,
		iterations, digest, expected_len, derived) != 1)
		goto out;

	match = CRYPTO_memcmp(expected, derived, (size_t)expected_len) == 0;

out:
	free(sha);
	free(salt);
	free(encoded);
	free(expected);
	free(derived);
	free(raw_salt);
	return match;
}
