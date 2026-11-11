/* The C library functions Mbed TLS calls (and GCC emits calls to), on liblv2's, which is what Sony's
 * libssl uses: the module links no libc of its own. strstr is the one liblv2 doesn't have. */

#include <stdarg.h>
#include <stddef.h>

void *_sys_memcpy(void *destination, const void *source, size_t size);
void *_sys_memset(void *destination, int value, size_t size);
int _sys_memcmp(const void *a, const void *b, size_t size);
void *_sys_memmove(void *destination, const void *source, size_t size);
size_t _sys_strlen(const char *text);
int _sys_strcmp(const char *a, const char *b);
char *_sys_strchr(const char *text, int character);
char *_sys_strrchr(const char *text, int character);
int _sys_vsnprintf(char *buffer, size_t size, const char *format, va_list arguments);

void *memcpy(void *destination, const void *source, size_t size)
{
	return _sys_memcpy(destination, source, size);
}

void *memset(void *destination, int value, size_t size)
{
	return _sys_memset(destination, value, size);
}

int memcmp(const void *a, const void *b, size_t size)
{
	return _sys_memcmp(a, b, size);
}

void *memmove(void *destination, const void *source, size_t size)
{
	return _sys_memmove(destination, source, size);
}

size_t strlen(const char *text)
{
	return _sys_strlen(text);
}

int strcmp(const char *a, const char *b)
{
	return _sys_strcmp(a, b);
}

char *strchr(const char *text, int character)
{
	return _sys_strchr(text, character);
}

char *strrchr(const char *text, int character)
{
	return _sys_strrchr(text, character);
}

/* Character by character, so it never reads past the haystack's end */
char *strstr(const char *haystack, const char *needle)
{
	for (;; ++haystack) {
		size_t at = 0;
		while (needle[at] != '\0' && haystack[at] == needle[at])
			++at;
		if (needle[at] == '\0')
			return (char *)haystack;
		if (*haystack == '\0')
			return NULL;
	}
}

int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments)
{
	return _sys_vsnprintf(buffer, size, format, arguments);
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int written = _sys_vsnprintf(buffer, size, format, arguments);
	va_end(arguments);
	return written;
}
