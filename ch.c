#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PATH "./arquivo.txt"


int main()
{  
char vet[32];
char msg[16];
int i,batata;
    int fd = open(PATH, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    printf("Invoking 'listProcessInfo' system call\n");

   printf("Digite a sua msg.\n");
   scanf("%[^\n]s",msg);
	
	batata=strlen(msg);
	
	for(i=strlen(msg); i<16;i++){
	msg[i]='0';	
	}
	msg[16]='\0';
         
    ssize_t ret_status = syscall(333, fd, msg , batata); 

    fd = open(PATH, O_RDONLY| O_CREAT, 0666);

         ret_status = syscall(334, fd, vet, batata);
	
	printf("Foiii: %s\n", vet);
    if(ret_status == 0) 
         printf("System call 'listProcessInfo' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("System call 'listProcessInfo' did not execute as expected\n");
         
     return 0;
}



