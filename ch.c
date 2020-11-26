#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PATH "./arquivo.txt"


int main()
{  
char vet[256];
char msg[128];
int i,nbytes;
    int fd = open(PATH, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    printf("Invoking 'listProcessInfo' system call\n");

   printf("\nDigite a sua msg:\n\n");
   scanf("%[^\n]s",msg);
	
	nbytes=strlen(msg);
	
	for(i=strlen(msg); i<128;i++){
	msg[i]='0';	
	}
	msg[128]='\0';
         
    ssize_t ret_status = syscall(333, fd, msg , nbytes); 

    fd = open(PATH, O_RDONLY| O_CREAT, 0666);

         ret_status = syscall(334, fd, vet, nbytes);
	
	printf("\nMensagem Final: %s\n\n", vet);
    if(ret_status == 0) 
         printf("System call 'listProcessInfo' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("System call 'listProcessInfo' did not execute as expected\n");
         
     return 0;
}
