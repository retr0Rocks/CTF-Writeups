#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int rounds = 1;

void setup() {
  setvbuf(stderr, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
}

int main() {
  setup();
  char format[0x100];
  while (rounds != 0) {
    puts("This time it won't be easy, take your time and stack your way up to glory !!");
    printf(">>> ");
    fgets(format, 0x100, stdin);
    printf(format);
    rounds--;
  }
  return 0;
}
