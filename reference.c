int strlen(char *c) {
    int len = 0;
    while (*c++) {
        len++;
    }
    return len;
}

void strcpy(char *dst, char *src) {
    while (*src) {
        *dst = *src;
        src++;
        dst++;
    }
        *dst = 0;
}

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

void strcat(char *dst, char *src) {
    dst += strlen(dst);
    strcpy(dst, src);
}

int const_func() {
    return 666;
}

int one_arg(int i) {
    return i + 1000;
}

int atoi(char *val) {
    int res = 0;
    for (int i = 0; i < strlen(val); i++) {
        res = res * 10 + val[i] - '0';
    }
    return res;
}

int two_arg(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int mul(unsigned a, unsigned b) {
    return a * b;
}

int xor_12(int a) {
    return a ^ 12;
}

int imul(int a, int b) {
    return a * b;
}

char hexchar(int i) {
    if (i >= 0 && i < 10) { return '0' + i; }
    if (i >= 10 && i < 16) { return 'a' + i - 10; }
    return '?';
}

void hexencode(unsigned char *str, char *outbuf) {
    for (; *str; str++) {
        *outbuf++ = hexchar(*str >> 4);
        *outbuf++ = hexchar(*str & 15);
    }
    *outbuf = 0;
}

unsigned int crc32(unsigned char *message) {
   int i, j;
   unsigned int byte, crc, mask;

   i = 0;
   crc = 0xFFFFFFFF;
   while (message[i] != 0) {
      byte = message[i];
      crc = crc ^ byte;
      for (j = 7; j >= 0; j--) {
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
      i = i + 1;
   }
   return ~crc;
}

int main() {
    char d[1000];
    hexencode("ala ma kota", d);
    puts(d);
}
