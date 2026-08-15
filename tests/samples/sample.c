#include <stdio.h>

#define CURLOPT_PROXYPASSWORD 1
#define CURLOPT_XOAUTH2_BEARER 2
#define CURLOPT_PASSWORD 3
#define CURLOPT_USERPWD 4
#define CURLOPT_PROXYUSERPWD 5
#define CURLOPT_KEYPASSWD 6

void easy_setopt(void *a, int b, char*c){
    printf("%p, %d, %s\n", a, b, c);
}

int main(int argc, char **argv){
    void *curl = NULL;
    easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, "K5aS1fMnmhQJMRKRw75Mwm3AVuRVZT39-v0hDyAfeqOYJZ3ji9mhO4lQ_oN2aT2Juugcd5CYqTso");
    easy_setopt(curl, CURLOPT_PASSWORD, "KiASRCRiGFLPDiIdZZLBXaNzXCMEdYIs");
    easy_setopt(curl, CURLOPT_USERPWD, "root:dkb82VddSD");
    easy_setopt(curl, CURLOPT_PROXYPASSWORD, ")d!~ORI8ed7293eg@w8&()");
    easy_setopt(curl, CURLOPT_PROXYUSERPWD, "user:NjWbc62SosW");
    easy_setopt(curl, CURLOPT_KEYPASSWD, "lT3t7TlhmUkNbDO4rXkmWlQ2LRymzhDKYb");
    return 0;
}
