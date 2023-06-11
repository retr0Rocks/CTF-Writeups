#include <stdio.h>
#include <stdlib.h>


void cleanup() {
  printf("see you again\n");
  exit(0);
}
void win() {
  system("/bin/sh");
}

unsigned long long leaky_sink() {
    unsigned long long leak;
    __asm__ __volatile__("mov %%fs:0x0, %0" : "=r" (leak));
    return leak;
}

int main() {
  int choice;
  unsigned long long addr;
  unsigned long long *where;
  unsigned long long what;
  char ptr[24];
  int do_read = 2, do_write = 1;
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);
  setvbuf(stderr, 0, _IONBF, 0);
  atexit(cleanup);
  for (;;) {
    printf("1. Read (%d Remaining)\n", do_read);
    printf("2. Write (%d Remaining)\n", do_write);
    printf("choice: ");
    scanf("%d", &choice);
    switch(choice){
      case 1:
        if (do_read) {
          printf("where? ");
          scanf("%llu", &addr);
          where = (unsigned long long *) addr;
          printf("data : %llx\n", *where);
          do_read--;
        } else {
          printf("ONLY ONE TIME\n");
        }
        break;
      case 2:
        if (do_write) {
          printf("where? ");
          scanf("%llu", &addr);
          where = (unsigned long long *) addr;
          printf("what ?");
          scanf("%llu", addr);
          do_write = 0;
        } else {
          printf("ONLY ONE TIME\n");
        }
        break;
      case 1337:
        printf("leaky sinks gift as always 0x%llx\n", leaky_sink());
        break;
      case 0:
        exit(0);
    } 
  }
}
