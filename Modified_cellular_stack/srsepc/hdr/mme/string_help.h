//
// Created by ishtiaq on 9/20/23.
//

#pragma once

#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

void reverse(char str[], int length);
char* custom_itoa(int num, int base);
int custom_atoi(const char* str);
char *string_trim_whitespace(const char *str);
int findFirst(char *str, char target);
int countChar(const char *str, char target);
char **splitStr(char *str, char target, int *splitCount, int trim);
#ifdef __cplusplus
}
#endif