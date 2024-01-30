// (2) gcc の -Wl,--wrap=malloc オプションを使う方法

// $ gcc -g -fno-pie -no-pie -Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=calloc -Wl,--wrap=realloc my_malloc2.c 
// 最後に一緒にコンパイルするファイルを指定．検体の再コンパイルが必要
#define _GNU_SOURCE 
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <wchar.h>

extern void *__real_malloc (size_t);
extern void __real_free (void *);
extern void *__real_calloc (size_t, size_t);
extern int __real_posix_memalign (void **, size_t, size_t);
extern void *__real_realloc (void *, size_t);
#if 0
extern void *__real_reallocarray (void *, size_t, size_t);
#endif
extern char *__real_strdup (const char *s);
extern char *__real_strndup (const char *s, size_t n);
extern wchar_t *__real_wcsdup (const wchar_t *s);
extern int __real_asprintf (char **strp, const char *fmt, ...);
extern void *__real_memcpy (void *dest, const void *src, size_t n);
extern void *__real_mempcpy (void *dest, const void *src, size_t n);
extern void *__real_memmove (void *dest, const void *src, size_t n);
extern void *__real_memset (void *s, int c, size_t n);
extern char *__real_strcpy (char *dest, const char *src);
extern char *__real_strncpy (char *dest, const char *src, size_t n);

static char buf [1024];
#define WATCHED_ADDR ((void *)0x42bbe0)
#undef NDEBUG
// #define NDEBUG

void *__wrap_malloc (size_t size)
{
    void *ptr = __real_malloc (size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_malloc: size=%ld, ptr=%p\n", size, ptr);
        fputs (buf, stderr); 
    }
#endif
#if 0     // PIN_Backtrace の動作確認用
    void *rbp, *ret_addr;
    asm volatile ("movq %%rbp, %0": "=m"(rbp));
    asm volatile ("movq 8(%%rbp), %0": "=r"(ret_addr));
    fprintf (stderr, "plp_malloc: rbp=%p, ret_addr=%p\n", rbp, ret_addr);
#endif
    return ptr;
}

void __wrap_free (void *ptr)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_free: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

void *__wrap_calloc (size_t nmemb, size_t size)
{
    void *ptr = __real_calloc (nmemb, size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_calloc: ptr=%p, nmemb=%ld, size=%ld\n", ptr, nmemb, size);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

int __wrap_posix_memalign (void **memptr, size_t align, size_t size)
{
    int ret = __real_posix_memalign (memptr, align, size);
#if !defined(NDEBUG) || 1
    if (1 || *memptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_posix_memalign: memptr=%p, *memptr=%p, align=%ld, size=%ld, ret=%d\n", memptr, *memptr, align, size, ret);
        fputs (buf, stderr); 
    }
#endif
    return ret;
}

void *__wrap_realloc (void *ptr, size_t size)
{
    void *ptr2 = __real_realloc (ptr, size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR || ptr2==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_realloc: ptr=%p->%p, size=%ld\n", ptr, ptr2, size);
        fputs (buf, stderr); 
    }
#endif
    return ptr2;
}

#if 0
void *__wrap_reallocarray (void *ptr, size_t nmemb, size_t size)
{
    void *ptr2 = __real_reallocarray (ptr, nmemb, size);
#if !defined (NDEBUG)
    write (2, "__wrap_reallocarray!\n", 21);
#endif
    return ptr2;
}
#endif

char *__wrap_strdup (const char *s)
{
    void *s2 = __real_strdup (s);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_strdup!\n", 15);
#endif
    return s2;
}

char *__wrap_strndup (const char *s, size_t n)
{
    void *s2 = __real_strndup (s, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_strndup!\n", 16);
#endif
    return s2;
}

wchar_t *__wrap_wcsdup (const wchar_t *s)
{
    void *s2 = __real_wcsdup (s);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_wcsdup!\n", 15);
#endif
    return s2;
}

void *__wrap_memcpy (void *dest, const void *src, size_t n)
{
    void *ret = __real_memcpy (dest, src, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_memcpy!\n", 15);
#endif
    return ret;
}

void *__wrap_mempcpy (void *dest, const void *src, size_t n)
{
    void *ret = __real_mempcpy (dest, src, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_mempcpy!\n", 16);
#endif
    return ret;
}

void *__wrap_memmove (void *dest, const void *src, size_t n)
{
    void *ret = __real_memmove (dest, src, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_memmove!\n", 16);
#endif
    return ret;
}

void *__wrap_memset (void *s, int c, size_t n)
{
    void *ret = __real_memset (s, c, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_memset!\n", 15);
#endif
    return ret;
}

int __wrap_asprintf (char **strp, const char *fmt, ...)
{
    va_list argp;
    va_start (argp, fmt);
    int ret = vasprintf (strp, fmt, argp);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_asprintf!\n", 15);
#endif
    va_end (argp);
    return ret;
}

char *__wrap_strcpy (char *dest, const char *src)
{
    void *ret = __real_strcpy (dest, src);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_strcpy!\n", 15);
#endif
    return ret;
}

char *__wrap_strncpy (char *dest, const char *src, size_t n)
{
    void *ret = __real_strncpy (dest, src, n);
#if !defined (NDEBUG) && 0
    write (2, "__wrap_strncpy!\n", 16);
#endif
    return ret;
}

// ====== new系 
// operator new[](unsigned long)
void *__wrap__Znam (size_t size)
{
    void *ptr = __real_malloc (size);
    
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new[]: size=%ld, ptr=%p\n", size, ptr);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new(unsigned long)
void *__wrap__Znwm (size_t size)
{
    void *ptr = __real_malloc (size);
    
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new: size=%ld, ptr=%p\n", size, ptr);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new(unsigned long, std::nothrow_t const&)
void *__wrap__ZnwmRKSt9nothrow_t (size_t size, void *nothrow)
{
    void *ptr = __real_malloc (size);
    
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new_nothrow: size=%ld, ptr=%p\n", size, ptr);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new[](unsigned long, std::nothrow_t const&)
void *__wrap__ZnamRKSt9nothrow_t (size_t size, void *nothrow)
{
    void *ptr = __real_malloc (size);
    
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new[]_nothrow: size=%ld, ptr=%p\n", size, ptr);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new(unsigned long, std::align_val_t)
void *__wrap__ZnwmSt11align_val_t (size_t size, size_t align)
{
    void *ptr = __real_malloc (size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new_align: size=%ld, ptr=%p, align=%ld\n", size, ptr, align);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new(unsigned long, std::align_val_t, std::nothrow_t const&)
void *__wrap__ZnwmSt11align_val_tRKSt9nothrow_t (size_t size, size_t align, void* nothrow)
{
    void *ptr = __real_malloc (size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new_align_nothrow: size=%ld, ptr=%p, align=%ld\n", size, ptr, align);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new[](unsigned long, std::align_val_t)
void *__wrap__ZnamSt11align_val_t (size_t size, size_t align)
{
    void *ptr = __real_malloc (size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new[]_align: size=%ld, ptr=%p, align=%ld\n", size, ptr, align);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// operator new[](unsigned long, std::align_val_t, std::nothrow_t const&)
void *__wrap__ZnamSt11align_val_tRKSt9nothrow_t (size_t size, size_t align, void *nothrow)
{
    void *ptr = __real_malloc (size);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_new[]_align_nothrow: size=%ld, ptr=%p, align=%ld\n", size, ptr, align);
        fputs (buf, stderr); 
    }
#endif
    return ptr;
}

// ====== delete系 
// operator delete(void*)
void __wrap__ZdlPv (void *ptr)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*)
void __wrap__ZdaPv (void *ptr)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete(void*, unsigned long)
void __wrap__ZdlPvm (void *ptr)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete_sized: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*, unsigned long)
void __wrap__ZdaPvm (void *ptr)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]_sized: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete(void*, unsigned long, std::align_val_t)
void __wrap__ZdlPvmSt11align_val_t (void* ptr, size_t size, size_t align)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete_sized_align: ptr=%p, size=%ld, align=%ld\n", ptr, size, align);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete(void*, std::nothrow_t const&)
void __wrap__ZdlPvRKSt9nothrow_t (void* ptr, void* nothrow)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete_nothrow: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete(void*, std::align_val_t)
void __wrap__ZdlPvSt11align_val_t (void* ptr, size_t align)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete_align: ptr=%p, align=%ld\n", ptr, align);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete(void*, std::align_val_t, std::nothrow_t const&)
void __wrap__ZdlPvSt11align_val_tRKSt9nothrow_t (void* ptr, size_t align, void *nothrow)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete_align_nothrow: ptr=%p, align=%ld\n", ptr, align);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*, unsigned long, std::align_val_t)
void __wrap__ZdaPvmSt11align_val_t (void* ptr, size_t size, size_t align)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]_sized_align: ptr=%p, align=%ld\n", ptr, align);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*, std::nothrow_t const&)
void __wrap__ZdaPvRKSt9nothrow_t (void* ptr, void *nothrow)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]_nothrow: ptr=%p\n", ptr);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*, std::align_val_t)
void __wrap__ZdaPvSt11align_val_t (void* ptr, size_t align)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]_align: ptr=%p, align=%ld\n", ptr, align);
        fputs (buf, stderr); 
    }
#endif
}

// operator delete[](void*, std::align_val_t, std::nothrow_t const&)
void __wrap__ZdaPvSt11align_val_tRKSt9nothrow_t (void* ptr, size_t align, void *nothrow)
{
    __real_free (ptr);
#if !defined(NDEBUG)
    if (ptr==WATCHED_ADDR) {
        snprintf (buf, sizeof (buf), "__wrap_delete[]_align_nothrow: ptr=%p, align=%ld\n", ptr, align);
        fputs (buf, stderr); 
    }
#endif
}
// ====== ここまで
