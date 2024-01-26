#include <stdio.h>
#include <openssl/md5.h>

char buf[12];

int calc_md5(int a1, int a2)
{

}

int auth(int len)
{
    char a[8];
    char *hash;
    int decoded;

    memcpy(&decoded, &buf, len);
    hash = (char *)calc_md5((int)a, 12);
    printf("hash: %s\n", hash);
    return strcmp(hash, "f87cd601aa7fedca99018a8be88eda34") == 0;
}

void win()
{
    printf("You win!\n");
    system("cat /flag");
}

int main(int argc, char **argv, char **envp)
{
    int decoded=0;
    char input[30];
    int len=0;
    
    memset(input, 0, sizeof(input));
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);

    printf("Enter the password: ");
    readn(0, input, 30);
    memset(&buf, 0, 12);

    len = Base64Decode(input, &decoded);
    if (len != 12)
    {
        printf("Wrong password!\n");
        exit(0);
    }
    memcpy(&buf, decoded, len);
    if(auth(len)==1){
        win();
    }
    return 0;
}