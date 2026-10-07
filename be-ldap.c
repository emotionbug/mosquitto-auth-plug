/*
 * Copyright (c) 2014 Jan-Piet Mens <jp@mens.de>
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
 * 3. Neither the name of mosquitto nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef BE_LDAP

#define   LDAP_DEPRECATED 1

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto/libmosquitto.h>
#include "backends.h"
#include "be-ldap.h"
#include "log.h"
#include "hash.h"

struct ldap_backend {
	char *ldap_uri;
	char *connstr;		/* ldap_initialize() wants scheme://host:port  only */
	LDAPURLDesc *lud;	
	LDAP *ld;
	char *user_uri;
	char *superquery;
	char *aclquery;
	int acldeny;
};

static char *get_bool(char *option, char *defval)
{
	char *flag = p_stab(option);
	flag = flag ? flag : defval;
	if (!strcmp("true", flag) || !strcmp("false", flag)) {
		return flag;
	}
	_log(LOG_NOTICE, "WARN: %s is unexpected value -> %s", option, flag);
	return defval;
}

static char *escape_filter_value(const char *value)
{
	const unsigned char *src;
	char *escaped, *dst;
	size_t length = 0;

	if (value == NULL)
		return NULL;
	for (src = (const unsigned char *)value; *src; src++) {
		if (*src == '*' || *src == '(' || *src == ')' || *src == '\\') {
			if (length > SIZE_MAX - 3)
				return NULL;
			length += 3;
		} else {
			if (length == SIZE_MAX)
				return NULL;
			length++;
		}
	}

	escaped = malloc(length + 1);
	if (escaped == NULL)
		return NULL;
	for (src = (const unsigned char *)value, dst = escaped; *src; src++) {
		switch (*src) {
		case '*':
			memcpy(dst, "\\2a", 3);
			dst += 3;
			break;
		case '(':
			memcpy(dst, "\\28", 3);
			dst += 3;
			break;
		case ')':
			memcpy(dst, "\\29", 3);
			dst += 3;
			break;
		case '\\':
			memcpy(dst, "\\5c", 3);
			dst += 3;
			break;
		default:
			*dst++ = (char)*src;
		}
	}
	*dst = '\0';
	return escaped;
}

static char *build_user_filter(const char *filter_template, const char *username)
{
	const char *src;
	char *escaped = NULL, *filter = NULL, *dst;
	size_t markers = 0, template_len, escaped_len, result_len;

	if (filter_template == NULL)
		return NULL;
	escaped = escape_filter_value(username);
	if (escaped == NULL)
		return NULL;
	for (src = filter_template; *src; src++)
		markers += *src == '@';
	template_len = strlen(filter_template);
	escaped_len = strlen(escaped);
	if (markers != 0 && escaped_len > (SIZE_MAX - template_len - 1) / markers) {
		free(escaped);
		return NULL;
	}
	result_len = template_len - markers + markers * escaped_len;
	filter = malloc(result_len + 1);
	if (filter == NULL) {
		free(escaped);
		return NULL;
	}

	for (src = filter_template, dst = filter; *src; src++) {
		if (*src == '@') {
			memcpy(dst, escaped, escaped_len);
			dst += escaped_len;
		} else {
			*dst++ = *src;
		}
	}
	*dst = '\0';
	free(escaped);
	return filter;
}

void *be_ldap_init()
{
	struct ldap_backend *conf;
	char *uri;
	char *binddn, *bindpw;
	char *opt_flag;
	int rc, opt;
	size_t len;

	_log(LOG_DEBUG, "}}}} LDAP");

	uri = p_stab("ldap_uri");
	binddn = p_stab("binddn");
	bindpw = p_stab("bindpw");

	if (!uri) {
		_fatal("Mandatory option 'ldap_uri' is missing");
		return (NULL);
	}

	if (!ldap_is_ldap_url(uri)) {
		_fatal("Mandatory option 'ldap_uri' doesn't look like an LDAP URI");
		return (NULL);
	}

	if ((conf = (struct ldap_backend *)calloc(1, sizeof(struct ldap_backend))) == NULL)
		return (NULL);

	conf->ldap_uri = strdup(uri);
	if (conf->ldap_uri == NULL) {
		free(conf);
		return NULL;
	}
	if (ldap_url_parse(uri, &conf->lud) != 0) {
		be_ldap_destroy(conf);
		_fatal("Cannot parse ldap_uri");
		return (NULL);
	}

	/* ldap_initialize() allows schema://host:port only; build
	 * an appropriate string from what we have, to use later also.
	 */

	len = strlen(conf->lud->lud_scheme) + strlen(conf->lud->lud_host) + 15;
	if ((conf->connstr = malloc(len)) == NULL) {
		be_ldap_destroy(conf);
		_fatal("Out of memory");
		return (NULL);
	}
	snprintf(conf->connstr, len, "%s://%s:%d", conf->lud->lud_scheme, conf->lud->lud_host, conf->lud->lud_port);
	if (ldap_initialize(&conf->ld, conf->connstr) != LDAP_SUCCESS) {
		be_ldap_destroy(conf);
		_fatal("Cannot ldap_initialize");
		return (NULL);
	}

	opt = LDAP_VERSION3;
	ldap_set_option(conf->ld, LDAP_OPT_PROTOCOL_VERSION, &opt);

	if ((rc = ldap_simple_bind_s(conf->ld, binddn, bindpw)) != LDAP_SUCCESS) {
		be_ldap_destroy(conf);
		_fatal("Cannot bind to LDAP: %s", ldap_err2string(rc));
		return (NULL);
	}

	// conf->superquery	= p_stab("superquery");
	// conf->aclquery		= p_stab("aclquery");

	opt_flag = get_bool("ldap_acl_deny", "false");
	if (!strcmp("true", opt_flag))
		conf->acldeny = 1;

	return ((void *)conf);
}

void be_ldap_destroy(void *handle)
{
	struct ldap_backend *conf = (struct ldap_backend *)handle;

	if (conf) {
		if (conf->lud != NULL)
			ldap_free_urldesc(conf->lud);
		free(conf->ldap_uri);

		if (conf->connstr)
			free(conf->connstr);
		if (conf->ld)
			ldap_unbind(conf->ld);
		free(conf);
	}
}

/*
 * Open a new connection to LDAP so that we don't lose the exising
 * binddn/pw. Check if the user's `dn' can bind with `password'.
 * Return T/F. `connstr' is a scheme://host:port thing.
 */

static int user_bind(char *connstr, char *dn, const char *password)
{
	LDAP *ld = NULL;
	int opt, rc;

	if (ldap_initialize(&ld, connstr) != LDAP_SUCCESS) {
		_log(1, "Cannot ldap_initialize-2");
		return (FALSE);
	}

	opt = LDAP_VERSION3;
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &opt);

	if ((rc = ldap_simple_bind_s(ld, dn, password)) != LDAP_SUCCESS) {
		_log(1, "Cannot bind to LDAP as %s: %s", dn, ldap_err2string(rc));
		ldap_unbind(ld);
		return (FALSE);
	}

	ldap_unbind(ld);
	return (TRUE);

}

int be_ldap_getuser(void *handle, const char *username, const char *password, char **phash, const char *clientid)
{
	struct ldap_backend *conf = (struct ldap_backend *)handle;
	LDAPMessage *msg = NULL, *entry;
	int rc;
	char *filter, *dn;

	// printf("+++++++++++ GET %s USERNAME [%s] (%s)\n", conf->ldap_uri, username, password);

	filter = build_user_filter(conf->lud->lud_filter, username);
	if (filter == NULL)
		return BACKEND_ERROR;

	rc = ldap_search_s(conf->ld,
		conf->lud->lud_dn,
		conf->lud->lud_scope,
		filter,
		conf->lud->lud_attrs,
		0,
		&msg);
	free(filter);
	if (rc != LDAP_SUCCESS) {
		_log(LOG_NOTICE, "Cannot search LDAP for user %s: %s", username, ldap_err2string(rc));
		if (msg != NULL)
			ldap_msgfree(msg);
		return BACKEND_ERROR;
	}

	if (ldap_count_entries(conf->ld, msg) != 1) {
		_log(1, "LDAP search for %s returns != 1 entry", username);
		ldap_msgfree(msg);
		return BACKEND_DEFER;
	}

	rc = BACKEND_DEFER;
	if ((entry = ldap_first_entry(conf->ld, msg)) != NULL) {
		dn = ldap_get_dn(conf->ld, entry);
		if (dn != NULL && user_bind(conf->connstr, dn, password)) {
			rc = BACKEND_ALLOW;
		}
		if (dn != NULL)
			ldap_memfree(dn);
	}
	ldap_msgfree(msg);
	return rc;
}

/*
 * Return T/F if user is superuser
 */

int be_ldap_superuser(void *handle, const char *username)
{
	return BACKEND_DEFER;
}

/*
 * Check ACL.
 * username is the name of the connected user attempting
 * to access
 * topic is the topic user is trying to access (may contain
 * wildcards)
 * acc is desired type of access: read/write
 *	for subscriptions (READ) (1)
 *	for publish (WRITE) (2)
 *
 * SELECT topic FROM table WHERE username = '%s' AND (acc & %d)		// may user SUB or PUB topic?
 * SELECT topic FROM table WHERE username = '%s'              		// ignore ACC
 */

int be_ldap_aclcheck(void *handle, const char *clientid, const char *username, const char *topic, int acc)
{
	struct ldap_backend *conf = (struct ldap_backend *)handle;

	return (conf->acldeny ? BACKEND_DENY : BACKEND_ALLOW);
}
#endif /* BE_LDAP */
