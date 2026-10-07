#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "envs.h"
#include "log.h"

int get_sys_envs(char *envs, const char *delim_env, const char *delim_key, char *params_key[], char *env_name[], char *env_value[])
{
	char *tk;
	int params_cnt = 0;

	tk = strtok(envs, delim_env);
	while (tk != NULL && params_cnt < MAXPARAMSNUM) {
		params_key[params_cnt++] = tk;
		tk = strtok(NULL, delim_env);
	}

	int cnt = 0;

	while (cnt < params_cnt) {
		tk = strtok(params_key[cnt], delim_key);
		env_name[cnt] = strtok(NULL, delim_key);
		if (tk == NULL || env_name[cnt] == NULL)
			return -1;
		params_key[cnt] = tk;
		env_value[cnt] = getenv(env_name[cnt]) == NULL ? "NULL" : getenv(env_name[cnt]);
		cnt++;
	}
	return params_cnt;
}
