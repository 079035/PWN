# Main - heap
  
The program to attack is 'main'
The available options when running it are:

1. create node
2. delete node
3. read node
4. exit

When creating, deleting, and reading, the user can select index of the node to operate on.
Each node is a chunk of heap and Linux uses Fastbin or unsortbin to allocate future nodes depending on their size.

I declared three methods for each add, free, and show for faster pwning process.
First things first, there are different types of heap chunks.

Fastbin and unsortbin:

* Fastbins enable relatively small heap allocations faster by storing addresses of freed chunks of same size in a linked list form.
* Unsortbins are used for bigger sized chunks, and when freed, the content holds addresses pointing somewhere like previous and latter chunk.

An interesting fact about unsortbins is that when it is freed, if the last chunk of unsortbin is next to top chunk, the top chunk merges with the unsortbin and the content remains. However, if there is another chunk in between, the unsortbin will contain addresses pointing to libc addresses.

The exploit starts by creating one Fastbin(index=0, alias A), one unsortbin(index=1, alias B), and another Fastbin(index=2, ailas C).
Now, when I free B, C will act as a "guard" that will allow the unsortbin B to contain addresses of libc instead of its original content.

The exploit reads contents of B, leaking address of libc.
Calculating the offset results in exposing the libc start address.

Next, the exploit creates three new nodes D and E (small enough to be stored in Fastbin).
Freeing in order of D, E, and D makes the Fastbin to be linked as 'D -> E -> D -> 0x0'.

## House of Spirit

Using libc's base, I now can calculate address of malloc_hook using command `magic`.
By overwriting malloc_hook, the instruction will flow into an arbitrary address when malloc is called again.
When we malloc first chunk with same size(0x70- libc address starts with 7f), we can overwrite the FD of the third chunk's value since first and third fastbin point to the same chunk.
Now we have a fake chunk which points to malloc hook.

Then we get rid of two excess chunks by calling malloc so that the Fastbin points to the fake chunk.

## Exploit

We call malloc so the program tries to allocate the fake chunk.
To execute one gadget, we need to call realloc- to satisfy the context needed.
The fake chunk points to the malloc hook, and overwriting enough bites can overwrite realloc_hook as well since they are next to each other.
So we put one gadget on realloc_hook.

Finally, freeing twice(double free), triggers malloc -> malloc_hook ->  realloc_hook -> trigger one gadget -> shell.

### Done