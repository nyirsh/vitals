/* The C library functions vitals' libhttp calls (and GCC emits calls to), on liblv2's, as Sony's
 * libhttp and vitals-ssl/src/platform/libc.c do: the module links no libc of its own. liblv2 has no
 * strcspn or strstr; those are here */

#include <stdarg.h>
#include <stddef.h>

void *_sys_memcpy(void *destination, const void *source, size_t size);
void *_sys_memset(void *destination, int value, size_t size);
void *_sys_memmove(void *destination, const void *source, size_t size);
int _sys_memcmp(const void *a, const void *b, size_t size);
size_t _sys_strlen(const char *text);
int _sys_strncmp(const char *a, const char *b, size_t size);
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

void *memmove(void *destination, const void *source, size_t size)
{
	return _sys_memmove(destination, source, size);
}

int memcmp(const void *a, const void *b, size_t size)
{
	return _sys_memcmp(a, b, size);
}

size_t strlen(const char *text)
{
	return _sys_strlen(text);
}

int strcmp(const char *a, const char *b)
{
	while (*a != '\0' && *a == *b)
		++a, ++b;
	return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t size)
{
	return _sys_strncmp(a, b, size);
}

char *strchr(const char *text, int character)
{
	return _sys_strchr(text, character);
}

char *strrchr(const char *text, int character)
{
	return _sys_strrchr(text, character);
}

void *memchr(const void *data, int character, size_t size)
{
	const unsigned char *at = data;
	for (size_t i = 0; i < size; ++i)
		if (at[i] == (unsigned char)character)
			return (void *)(at + i);
	return NULL;
}

size_t strcspn(const char *text, const char *reject)
{
	size_t length = 0;
	while (text[length] != '\0' && _sys_strchr(reject, text[length]) == NULL)
		++length;
	return length;
}

char *strstr(const char *text, const char *word)
{
	size_t length = _sys_strlen(word);
	for (; *text != '\0'; ++text)
		if (_sys_strncmp(text, word, length) == 0)
			return (char *)text;
	return length == 0 ? (char *)text : NULL;
}

int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments)
{
	return _sys_vsnprintf(buffer, size, format, arguments);
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	int result = _sys_vsnprintf(buffer, size, format, arguments);
	va_end(arguments);
	return result;
}
