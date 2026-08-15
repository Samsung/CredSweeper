#include <stdio.h>

#define CURLOPT_PROXYPASSWORD 1
#define CURLOPT_XOAUTH2_BEARER 2

void easy_setopt(int a, int b, char*c){
    printf("%d, %d, %s\n", a, b, c);
    }

int main(int argc, char **argv){
    int curl = 0;
    easy_setopt(curl, CURLOPT_PROXYPASSWORD, "84c815a317ca518fb328a2fe2824528f82e12c055e0800f3cd8dc065e9ccc09b");
    easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, "fce4fbfb98b13d50adb16edfc97dcafa7d15429ec204b4c8763287aaec3adc4c");
    return 0;
}
