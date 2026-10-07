/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de> wendal
 * <wendal1985()gmai.com> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of mosquitto
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
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

#ifdef BE_JWT
#include "backends.h"
#include "be-jwt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "log.h"
#include "envs.h"
#include <curl/curl.h>

static int append_header(struct curl_slist **headers, const char *value)
{
	struct curl_slist *updated = curl_slist_append(*headers, value);
	if (updated == NULL)
		return -1;
	*headers = updated;
	return 0;
}

static int get_string_envs(CURL * curl, const char *required_env, char *querystring)
{
	char *data = NULL;
	char *escaped_key = NULL;
	char *escaped_val = NULL;
	char *env_string = NULL;

	char *params_key[MAXPARAMSNUM];
	char *env_names[MAXPARAMSNUM];
	char *env_value[MAXPARAMSNUM];
	int i, num = 0;

	//_log(LOG_DEBUG, "sys_envs=%s", sys_envs);

	env_string = strdup(required_env);
	if (env_string == NULL) {
		return (-1);
	}

	//_log(LOG_DEBUG, "env_string=%s", env_string);

	num = get_sys_envs(env_string, ",", "=", params_key, env_names, env_value);
	//sprintf(querystring, "");
	for (i = 0; i < num; i++) {
		escaped_key = curl_easy_escape(curl, params_key[i], 0);
		escaped_val = curl_easy_escape(curl, env_value[i], 0);
		if (escaped_key == NULL || escaped_val == NULL) {
			curl_free(escaped_key);
			curl_free(escaped_val);
			free(env_string);
			return -1;
		}

		//_log(LOG_DEBUG, "key=%s", params_key[i]);
		//_log(LOG_DEBUG, "escaped_key=%s", escaped_key);
		//_log(LOG_DEBUG, "escaped_val=%s", escaped_envvalue);

		data = (char *)malloc(strlen(escaped_key) + strlen(escaped_val) + 3);
		if (data == NULL) {
			curl_free(escaped_key);
			curl_free(escaped_val);
			free(env_string);
			return (-1);
		}
		if (strlen(querystring) + strlen(escaped_key) + strlen(escaped_val) + 3 > MAXPARAMSLEN) {
			free(data);
			curl_free(escaped_key);
			curl_free(escaped_val);
			free(env_string);
			return -1;
		}
		sprintf(data, "%s=%s&", escaped_key, escaped_val);
		if (i == 0) {
			sprintf(querystring, "%s", data);
		} else {
			strcat(querystring, data);
		}
		free(data);
		curl_free(escaped_key);
		curl_free(escaped_val);
	}

	free(env_string);
	return (num);
}

static int http_post(void *handle, char *uri, const char *clientid, const char *token, const char *topic, int acc, int method)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	CURL *curl = NULL;
	struct curl_slist *headerlist = NULL;
	int re;
	long respCode = 0;
	int ok = BACKEND_DEFER;
	char *url = NULL, *data = NULL, *token_header = NULL;
	char *escaped_token = NULL, *escaped_topic = NULL, *escaped_clientid = NULL;
	char *string_envs = NULL;
	int urllen;

	if (token == NULL) {
		return BACKEND_DEFER;
	}
	clientid = (clientid && *clientid) ? clientid : "";
	topic = (topic && *topic) ? topic : "";

	if ((curl = curl_easy_init()) == NULL) {
		return BACKEND_ERROR;
	}
	if (conf->hostheader != NULL && append_header(&headerlist, conf->hostheader) != 0)
		goto cleanup;
	if (append_header(&headerlist, "Expect:") != 0)
		goto cleanup;

	//_log(LOG_NOTICE, "u=%s p=%s t=%s acc=%d", username, password, topic, acc);

	// uri begins with a slash
	urllen = snprintf(NULL, 0, "%s://%s:%d%s",
		strcmp(conf->with_tls, "true") == 0 ? "https" : "http",
		conf->hostname ? conf->hostname : conf->ip,
		conf->port,
		uri);
	if (urllen < 0)
		goto cleanup;
	url = malloc((size_t)urllen + 1);
	if (url == NULL)
		goto cleanup;
	snprintf(url, (size_t)urllen + 1, "%s://%s:%d%s",
		strcmp(conf->with_tls, "true") == 0 ? "https" : "http",
		conf->hostname ? conf->hostname : conf->ip, conf->port, uri);

	escaped_token = curl_easy_escape(curl, token, 0);
	escaped_topic = curl_easy_escape(curl, topic, 0);
	escaped_clientid = curl_easy_escape(curl, clientid, 0);
	if (escaped_token == NULL || escaped_topic == NULL || escaped_clientid == NULL)
		goto cleanup;

	char string_acc[20];
	snprintf(string_acc, 20, "%d", acc);

	string_envs = (char *)calloc(1, MAXPARAMSLEN);
	if (string_envs == NULL) {
		goto cleanup;
	}

	//get the sys_env from here
		int env_num = 0;
	if (method == METHOD_GETUSER && conf->getuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->getuser_envs, string_envs);
	} else if (method == METHOD_SUPERUSER && conf->superuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->superuser_envs, string_envs);
	} else if (method == METHOD_ACLCHECK && conf->aclcheck_envs != NULL) {
		env_num = get_string_envs(curl, conf->aclcheck_envs, string_envs);
	}
	if (env_num == -1) {
		goto cleanup;
	}
	//----over-- --

		data = (char *)malloc(strlen(string_envs) + strlen(escaped_topic) + strlen(string_acc) + strlen(escaped_clientid) + 30);
	if (data == NULL) {
		goto cleanup;
	}
	sprintf(data, "%stopic=%s&acc=%s&clientid=%s",
		string_envs,
		escaped_topic,
		string_acc,
		escaped_clientid);

	_log(LOG_DEBUG, "url=%s", url);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	token_header = (char *)malloc(strlen(escaped_token) + strlen("Authorization: Bearer ") + 1);
	if (token_header == NULL) {
		goto cleanup;
	}
	sprintf(token_header, "Authorization: Bearer %s", escaped_token);
	if (append_header(&headerlist, token_header) != 0)
		goto cleanup;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

	re = curl_easy_perform(curl);
	if (re == CURLE_OK) {
		re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
		if (re == CURLE_OK && respCode >= 200 && respCode < 300) {
			ok = BACKEND_ALLOW;
		} else if (re == CURLE_OK && respCode >= 500) {
			ok = BACKEND_ERROR;
		} else {
			//_log(LOG_NOTICE, "http auth fail re=%d respCode=%d", re, respCode);
		}
	} else {
		_log(LOG_DEBUG, "http req fail url=%s re=%s", url, curl_easy_strerror(re));
		ok = BACKEND_ERROR;
	}

cleanup:
	if (curl != NULL)
		curl_easy_cleanup(curl);
	curl_slist_free_all(headerlist);
	free(url);
	free(data);
	free(string_envs);
	curl_free(escaped_token);
	free(token_header);
	curl_free(escaped_topic);
	curl_free(escaped_clientid);
	return (ok);
}

void *be_jwt_init()
{
	struct jwt_backend *conf;
	char *ip;
	char *getuser_uri;
	char *superuser_uri;
	char *aclcheck_uri;

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		_fatal("init curl fail");
		return (NULL);
	}
	if ((ip = p_stab("http_ip")) == NULL) {
		_fatal("Mandatory parameter `http_ip' missing");
		return (NULL);
	}
	if ((getuser_uri = p_stab("http_getuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_getuser_uri' missing");
		return (NULL);
	}
	if ((superuser_uri = p_stab("http_superuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_superuser_uri' missing");
		return (NULL);
	}
	if ((aclcheck_uri = p_stab("http_aclcheck_uri")) == NULL) {
		_fatal("Mandatory parameter `http_aclcheck_uri' missing");
		return (NULL);
	}
	conf = (struct jwt_backend *)malloc(sizeof(struct jwt_backend));
	if (conf == NULL) {
		curl_global_cleanup();
		return NULL;
	}
	conf->ip = ip;
	conf->hostname = NULL;
	conf->hostheader = NULL;
	conf->port = p_stab("http_port") == NULL ? 80 : atoi(p_stab("http_port"));
	if (p_stab("http_hostname") != NULL) {
		size_t header_len = strlen("Host: ") + strlen(p_stab("http_hostname")) + 1;
		conf->hostheader = (char *)malloc(header_len);
		if (conf->hostheader == NULL) {
			free(conf);
			curl_global_cleanup();
			return NULL;
		}
		conf->hostname = p_stab("http_hostname");
		snprintf(conf->hostheader, header_len, "Host: %s", p_stab("http_hostname"));
	}
	conf->getuser_uri = getuser_uri;
	conf->superuser_uri = superuser_uri;
	conf->aclcheck_uri = aclcheck_uri;

	conf->getuser_envs = p_stab("http_getuser_params");
	conf->superuser_envs = p_stab("http_superuser_params");
	conf->aclcheck_envs = p_stab("http_aclcheck_params");

	if (p_stab("http_with_tls") != NULL) {
		conf->with_tls = p_stab("http_with_tls");
	} else {
		conf->with_tls = "false";
	}

	_log(LOG_DEBUG, "with_tls=%s", conf->with_tls);
	_log(LOG_DEBUG, "getuser_uri=%s", getuser_uri);
	_log(LOG_DEBUG, "superuser_uri=%s", superuser_uri);
	_log(LOG_DEBUG, "aclcheck_uri=%s", aclcheck_uri);
	_log(LOG_DEBUG, "getuser_params=%s", conf->getuser_envs);
	_log(LOG_DEBUG, "superuser_params=%s", conf->superuser_envs);
	_log(LOG_DEBUG, "aclcheck_paramsi=%s", conf->aclcheck_envs);

	return (conf);
};
void be_jwt_destroy(void *handle)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;

	if (conf) {
		if (conf->hostheader) free(conf->hostheader);
		curl_global_cleanup();
		free(conf);
	}
};

int be_jwt_getuser(void *handle, const char *token, const char *pass, char **phash, const char *clientid)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	int re;
	if (token == NULL) {
		return BACKEND_DEFER;
	}
	re = http_post(handle, conf->getuser_uri, NULL, token, NULL, -1, METHOD_GETUSER);
	return re;
};

int be_jwt_superuser(void *handle, const char *token)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;

	return http_post(handle, conf->superuser_uri, NULL, token, NULL, -1, METHOD_SUPERUSER);
};

int be_jwt_aclcheck(void *handle, const char *clientid, const char *token, const char *topic, int acc)
{
	struct jwt_backend *conf = (struct jwt_backend *)handle;
	return http_post(conf, conf->aclcheck_uri, clientid, token, topic, acc, METHOD_ACLCHECK);
};

#endif /* BE_JWT */
