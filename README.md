# Greenbox

## About

Greenbox is my research side-project. It is still under construction, and there is still a lot of things to do (to be honest, this project is not very practical for now).

My goal is to help kickstart reverse-engineering of complex codebases by recognising and tagging typical functions performing operations like:
 - functions from various standard libraries (like memcpy, strlen, etc)
 - common hashes and cryptographic functions (like sha1, crc32, etc)
 - simple mathematical operations (like addition, division, xoring with constant, etc)
 - common obfuscations and malware patterns (maybe TEB traversing? And/or EH tricks? Detecting self-modifying code would be nice too)
 - no-op functions (wrappers for other functions, and subroutines with empty body)
 - you get the point.

## Technical summary

Greenbox is purely blackbox analyser (so far, considering goal of this project, I don't see any sensible reason for adding static features).

Currently only supported mode is signature scan - every function detected in source binary is executed with some preconditions (i.e. parameters on stack), and than postconditions are checked.
That means (simplifying things a bit) that when some function executed with parameters "2" and "3" gives back, we could guess that it's addition. Or when function called with string "banana" returns "72b302bf297a228a75730123efef7c41" we can be fairly sure that someone implemented md5.

## Example

Simple reference and playground for implemented signatures can be found in repository (in reference.c file). But for the sake of example, let's consider following, simple C program:

```c
void memcpy(char *dst, char *src, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

void memzero(char *dst, int n) {
    memset(dst, 0, n);
}

void memset(char *dst, int val, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = val;
    }
}

int main() {
}
```

Now compile it:

```
vagrant@precise64:/vagrant/greenbox$ gcc fun.c -o fun -std=c99 -m32
```

And than test it:

```
vagrant@precise64:/vagrant/greenbox$ python engine.py fun
signature memcpy found at offset 3e4
signature memzero found at offset 412
signature memset found at offset 434
signature noop found at offset 4e2
```
  
You can see that greenbox correctly recognised memset, memcpy and memzero, and even marked empty main function as no-op.
