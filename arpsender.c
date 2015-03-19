#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_ADDR_LEN 128

#define ADDR_LENGTH_OFFSET 4
#define ADDR_OFFSET 8

typedef unsigned char shsize_t;

typedef struct{
  shsize_t len;
  char addr[MAX_ADDR_LEN];
  char* hwtype;
  char* prototype;
  char* oper;
  char* protolen;
} arp_addr;

void print_address(char *packet)
{
  arp_addr hwaddr;
  int i;
  
  hwaddr.hwtype = malloc(4);
  
  memset(hwaddr.hwtype, 1, 4);
  memset(hwaddr.addr, 0, MAX_ADDR_LEN);

  hwaddr.len = (shsize_t) *(packet + ADDR_LENGTH_OFFSET);
  memcpy(hwaddr.addr, packet + ADDR_OFFSET, hwaddr.len);
  memcpy(hwaddr.hwtype, packet, 4);

  printf("Sender hardware address: ");
  for (i = 0; i < hwaddr.len - 1; i ++)
    printf("%02hhx::", hwaddr.addr[i]);
  printf("%02hhx\n", hwaddr.addr[hwaddr.len - 1]);  
  
  return;
}

int main(int argc, char *argv[])
{
  struct stat sbuf;
  char *packet;
  int fd;

  if (argc != 2){
    printf("Usage: %s <packet file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  if ((stat(argv[1], &sbuf)) < 0){
    printf("Error opening packet file\n");
    return EXIT_FAILURE;
  }

  if ((fd = open(argv[1], O_RDONLY)) < 0){
    printf("Error opening packet file\n");
    return EXIT_FAILURE;
  }

  if ((packet = (char *)malloc(sbuf.st_size * sizeof(char))) == NULL){
    printf("Error allocating memory\n");
    return EXIT_FAILURE;
  }

  if (read(fd, packet, sbuf.st_size) < 0){
    printf("Error reading packet from file\n");
    return EXIT_FAILURE;
  }
  close(fd);
  print_address(packet);
  free(packet);
  return EXIT_SUCCESS;
}

