#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "srsepc/hdr/mme/string_help.h"

//GeeksForGeeks: https://www.geeksforgeeks.org/implement-itoa/#
void reverse(char str[], int length){
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        end--;
        start++;
    }
}

// GeeksForGeeks: https://www.geeksforgeeks.org/implement-itoa/#
char* custom_itoa(int num, int base){
    char* str = (char*) malloc(sizeof(char ) * 16);
    int i = 0;
    int isNegative = 0;
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
    if (num < 0 && base == 10) {
        isNegative = 1;
        num = -num;
    }
    // Process individual digits
    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }
    // If number is negative, append '-'
    if (isNegative)
        str[i++] = '-';
    str[i] = '\0'; // Append string terminator
    // Reverse the string
    reverse(str, i);
    return str;
}

// GeeksForGeeks: https://www.geeksforgeeks.org/write-your-own-atoi/#
int custom_atoi(const char* str){
    int res = 0;
    for (int i = 0; str[i] != '\0'; i++){
        res = res * 10 + str[i] - '0';
    }
    return res;
}

/// StackOverflow: https://stackoverflow.com/a/26984026
// need to clean up returned pointer
char *string_trim_whitespace(const char *str) {
    char *res = (char *) malloc(sizeof(char ) * strlen(str));
    char *tmp = (char *) malloc(sizeof(char ) * strlen(str));
    char *fixed_tmp = tmp;

    strcpy(tmp, str);

    while (isspace((unsigned char) *tmp)) tmp++;
        if (*tmp) {
            char *p = tmp;
            while (*p) p++;
            while (isspace((unsigned char) *(--p)));
            p[1] = '\0';
        }
    strcpy(res, tmp);
    free(fixed_tmp);
    return res;
}

int findFirst(char *str, char target){
    int len = strlen(str);
    for(int i = 0; i < len && str[i]; i++){
        if(str[i] == target){
            return i;
        }
    }
    return -1;
}

int countChar(const char *str, char target){
    int count = 0;
    int len = strlen(str);
    for(int i = 0; i < len; i++){
        if(str[i] == target){
            count++;
        }
    }
    return count;
}

// need to clean up returned pointers
char **splitStr(char *str, char target, int *splitCount, int trim){
    *splitCount = countChar(str, target)+1;

//    printf("count = %d\n", *count);

    char *tempStrPtr = str;

    char **results = (char **) malloc(sizeof(char *) * (*splitCount));
    for(int i=0; i < (*splitCount); i++){
        char *buf = (char *) malloc(sizeof(char) * (strlen(str)+20));

        int pos = findFirst(tempStrPtr, target);

        if(i == (*splitCount)-1){
            strcpy(buf, tempStrPtr);
        }
        else if(pos < 0){
            printf("Error in split!!!\n");
            exit(1);
        }
        else if (pos == 0){
            strcpy(buf, "");
        }
        else{
            strncpy(buf, tempStrPtr, pos);
            buf[pos] = '\0';
        }

        if (trim){
            char *tmp = string_trim_whitespace(buf);
            strcpy(buf, tmp);
            free(tmp);
        }
        results[i] = buf;
        tempStrPtr = tempStrPtr + pos + 1;
    }
    return results;
}
