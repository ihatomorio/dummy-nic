#include <stdint.h>
#include <stdio.h>

void print_hex(void *buf, size_t buflen)
{
    uint8_t *poiner = (uint8_t *)buf;
    size_t offset = 0;

    for (offset = 0; offset < buflen; offset++)
    {
        printf("%02x", (uint8_t)*poiner);
        poiner++;

        if (offset % 16 == 15)
        {
            printf("\n");
            continue;
        }

        if (offset % 2 == 1)
        {
            printf(" ");
        }
    }

    printf("\n");
}
