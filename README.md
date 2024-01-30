# EarlyDLSAN
An early detection tool of  dangling pointers and memory leaks

## Disclaimer 

WARNING: this software is experimental, and not tested well.
This software is distributed in the hope that it will be interesting
and useful, but it has no warranty.  Any use is at your own risk.
We disclaim any liability of any kind of damages whatsoever resulting
from the use of this software.

## Platforms

Currently, we built and tested EarlyDLSAN
only on the following platform.

- Linux Ubuntu 20.04.3 LTS, Intel Pin 3.28, GCC 9.4.0

## Build 

- Before build, install [Intel Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html)
- Edit the PIN_ROOT's value in makefile
- Type `make`

## Example usage

- Type `make test-leak`

```
$ make test-leak
gcc -g -no-pie -U_FORTIFY_SOURCE -fno-omit-frame-pointer -Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=calloc -Wl,--wrap=posix_memalign -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=strndup -Wl,--wrap=wcsdup -Wl,--wrap=asprintf -Wl,--wrap=strcpy -Wl,--wrap=strncpy -Wl,--wrap=memcpy -Wl,--wrap=mempcpy -Wl,--wrap=memmove -Wl,--wrap=memset -Wl,--wrap=_Znwm -Wl,--wrap=_Znam -Wl,--wrap=_ZdlPv -Wl,--wrap=_ZdaPv -Wl,--wrap=_ZdaPvm -Wl,--wrap=_ZdlPvm -Wl,--wrap=_ZnamRKSt9nothrow_t -Wl,--wrap=_ZnwmRKSt9nothrow_t -Wl,--wrap=_ZnwmSt11align_val_t -Wl,--wrap=_ZnwmSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZnamSt11align_val_t -Wl,--wrap=_ZnamSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZdlPvmSt11align_val_t -Wl,--wrap=_ZdlPvRKSt9nothrow_t -Wl,--wrap=_ZdlPvSt11align_val_t -Wl,--wrap=_ZdlPvSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZdaPvmSt11align_val_t -Wl,--wrap=_ZdaPvRKSt9nothrow_t -Wl,--wrap=_ZdaPvSt11align_val_t -Wl,--wrap=_ZdaPvSt11align_val_tRKSt9nothrow_t ./test/leak.c -L. -lhook -o leak
/home/gondow/pin-3.28-98749-g6643ecee5-gcc-linux/pin  -t obj-intel64/MyPinTool.so -- ./leak
	image leak inst. done
	image ld-linux-x86-64.so.2 inst. skipped
	image [vdso] inst. skipped
	image libc.so.6 inst. skipped
999
leak.c::10 (0x401193) memory leak detected: heap object 12762a0, size = 4, RC = 0, alloc_loc=leak.c::6 (0x40116c), ::0 (0x7f052bd71083), ::0 (0x40109e), last_use_loc=leak.c::10 (0x401193), ::0 (0x7f052bd71083), ::0 (0x40109e), 
===== backtrace =====
	n=3
rsp=7ffc813857e0
leak.c::10 (0x401193): [0] ip=401193@main
::0 (0x7f052bd71083): [1] ip=7f052bd71083@__libc_start_main
::0 (0x40109e): [2] ip=40109e@_start
==================
=== malloc_map ===
0x12762a0, 0, 4, ALLOC, alloc: 40116c@leak.c::6 (0x40116c), 7f052bd71083@::0 (0x7f052bd71083), 40109e@::0 (0x40109e), free: last_use: 401193@leak.c::10 (0x401193), 7f052bd71083@::0 (0x7f052bd71083), 40109e@::0 (0x40109e), mark=0
	mem_set: 
	mem_loc:
	reg_set: 
	reg_loc:
==================
=== tag_reg_array ===
==================
=== tag_mem_map ===
==================
=== tag_stack_map ===
==================
leak 12762a0
```

- Type `make test-dang`

```
$ make test-dang
gcc -g -no-pie -U_FORTIFY_SOURCE -fno-omit-frame-pointer -Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=calloc -Wl,--wrap=posix_memalign -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=strndup -Wl,--wrap=wcsdup -Wl,--wrap=asprintf -Wl,--wrap=strcpy -Wl,--wrap=strncpy -Wl,--wrap=memcpy -Wl,--wrap=mempcpy -Wl,--wrap=memmove -Wl,--wrap=memset -Wl,--wrap=_Znwm -Wl,--wrap=_Znam -Wl,--wrap=_ZdlPv -Wl,--wrap=_ZdaPv -Wl,--wrap=_ZdaPvm -Wl,--wrap=_ZdlPvm -Wl,--wrap=_ZnamRKSt9nothrow_t -Wl,--wrap=_ZnwmRKSt9nothrow_t -Wl,--wrap=_ZnwmSt11align_val_t -Wl,--wrap=_ZnwmSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZnamSt11align_val_t -Wl,--wrap=_ZnamSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZdlPvmSt11align_val_t -Wl,--wrap=_ZdlPvRKSt9nothrow_t -Wl,--wrap=_ZdlPvSt11align_val_t -Wl,--wrap=_ZdlPvSt11align_val_tRKSt9nothrow_t -Wl,--wrap=_ZdaPvmSt11align_val_t -Wl,--wrap=_ZdaPvRKSt9nothrow_t -Wl,--wrap=_ZdaPvSt11align_val_t -Wl,--wrap=_ZdaPvSt11align_val_tRKSt9nothrow_t ./test/dang.c -L. -lhook -o dang
/home/gondow/pin-3.28-98749-g6643ecee5-gcc-linux/pin  -t obj-intel64/MyPinTool.so -- ./dang
	image dang inst. done
	image ld-linux-x86-64.so.2 inst. skipped
	image [vdso] inst. skipped
	image libc.so.6 inst. skipped
&p = 0x7fff1c010f90
TraceEnd: dangling pointer detected: 7fff1c010f90 (-> 200b2a0) @dang.c::14 (0x4011fa)
pointee:
0x200b2a0, 0, 4, DEALLOC, alloc: 4011c4@dang.c::9 (0x4011c4), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), free: 4011ec@dang.c::14 (0x4011ec), 4011ec@dang.c::14 (0x4011ec), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), last_use: 4011e7@dang.c::11 (0x4011e7), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), mark=0
	mem_set: 
	mem_loc:
	reg_set: 
	reg_loc:
mem_loc:
4011c4@dang.c::9 (0x4011c4), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), 
FuncEnd: dangling pointer detected: 7fff1c010f90 (-> 200b2a0) @dang.c::14 (0x401202)
pointee:
0x200b2a0, 0, 4, DEALLOC, alloc: 4011c4@dang.c::9 (0x4011c4), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), free: 4011ec@dang.c::14 (0x4011ec), 4011ec@dang.c::14 (0x4011ec), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), last_use: 4011e7@dang.c::11 (0x4011e7), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), mark=0
	mem_set: 
	mem_loc:
	reg_set: 
	reg_loc:
mem_loc:
4011c4@dang.c::9 (0x4011c4), 401215@dang.c::19 (0x401215), 7f2b5a8ea083@::0 (0x7f2b5a8ea083), 4010de@::0 (0x4010de), 
```

