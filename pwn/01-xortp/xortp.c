#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 128

ssize_t
get_otp(unsigned char *k, const size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
    	return -1;
    }

    if (read(fd, k, n) < 0) {
        close(fd);
    	return -1;
    }

    close(fd);
    return n;
}

ssize_t
read_file(char *fn, unsigned char *m)
{
    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
    	return -1;
    }

    ssize_t n = read(fd, m, BUF_SIZE);
    if (n < 0) {
    	return -1;
    }

    close(fd);
    return n;
}

int
main()
{
    char filename[BUF_SIZE];
    unsigned char m[BUF_SIZE];
    unsigned char k[BUF_SIZE];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    system("ls -ld *");

    printf("Which file would like to encrypt?\n");
    scanf("%s", filename);

    ssize_t length = read_file(filename, m);
    if (length < 0) {
        printf("Error: read_file\n");
    	return 0;
    }

    if (get_otp(k, length) < 0) {
        printf("Error: get_otp\n");
    	return 0;
    }

    // Output the XOR result
    for (ssize_t i = 0; i < length; ++i) {
    	printf("%02x", m[i] ^ k[i]);
    }
    printf("\n");

    return 0;
}
