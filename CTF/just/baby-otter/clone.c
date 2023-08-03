#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint64_t *gt()
{
    uint64_t *table = (uint64_t *)malloc(256 * sizeof(uint64_t));
    uint64_t tmp;
    uint64_t i, j;

    for (i = 0; i < 256; i++)
    {
        tmp = i;
        for (j = 0; j < 8; j++)
        {
            if (tmp & 1)
            {
                tmp = tmp >> 1;
                tmp = tmp ^ 0xedb88320;
            }
            else
            {
                tmp = tmp >> 1;
            }
        }
        table[i] = tmp;
    }

    return table;
}

uint64_t hh(uint8_t *input, size_t input_length)
{
    uint64_t *table = gt();
    uint64_t tmp = 0xffffffff;
    size_t i;

    for (i = 0; i < input_length; i++)
    {
        uint64_t byte = (uint64_t)input[i];
        uint64_t index = tmp ^ byte;
        index = index & 0xff;

        tmp = tmp >> 8;
        tmp = tmp ^ table[index];
    }

    free(table);

    return tmp ^ 0xffffffff;
}

int main()
{
    // Read input_length from standard input
    char buf[8];
    memset(buf, 0, 8);
    read(0, buf, 8);
    size_t input_length = atoi(buf);

    // Allocate memory for input array
    uint8_t *input = (uint8_t *)malloc(input_length * sizeof(uint8_t));

    read(0, input, input_length);

    // Call hh() function
    uint64_t result = hh(input, input_length);
    printf("%llu\n", result);

    if (result == 1725720156)
        printf("Solved\n");
    else
        printf("Failed\n");

    // Free memory for input array
    free(input);

    return 0;
}