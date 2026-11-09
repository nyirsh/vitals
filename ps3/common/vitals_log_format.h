#ifndef VITALS_LOG_FORMAT_H
#define VITALS_LOG_FORMAT_H

/* printf's format for the plugins with no C library (vitals_log_sink.h's VITALS_LOG_PLAIN), written
 * for them: %s %c %d %u %x %X and %%, with l or ll, a 0 flag and a width. out always ends in a NUL;
 * the return is how many characters are in it */

#include <stdarg.h>
#include <stdint.h>

static inline uint32_t vitals_log_vformat(char *out, uint32_t size, const char *format, va_list arguments)
{
	uint32_t used = 0;
#define VITALS_LOG_PUT(c)            \
	do {                             \
		if (used + 1 < size)         \
			out[used++] = (c);       \
	} while (0)
	for (; *format != '\0'; ++format) {
		if (*format != '%') {
			VITALS_LOG_PUT(*format);
			continue;
		}
		++format;
		int zero = 0, longs = 0;
		unsigned width = 0;
		if (*format == '0') {
			zero = 1;
			++format;
		}
		for (; *format >= '0' && *format <= '9'; ++format)
			width = width * 10 + (unsigned)(*format - '0');
		for (; *format == 'l'; ++format)
			++longs;
		char c = *format;
		if (c == '\0')
			break;
		if (c == '%') {
			VITALS_LOG_PUT('%');
		} else if (c == 'c') {
			VITALS_LOG_PUT((char)va_arg(arguments, int));
		} else if (c == 's') {
			const char *text = va_arg(arguments, const char *);
			for (text = text != 0 ? text : "(null)"; *text != '\0'; ++text)
				VITALS_LOG_PUT(*text);
		} else if (c == 'd' || c == 'u' || c == 'x' || c == 'X') {
			uint64_t value;
			int negative = 0;
			if (c == 'd') {
				int64_t number = longs ? va_arg(arguments, long long) : va_arg(arguments, int);
				negative = number < 0;
				value = negative ? 0 - (uint64_t)number : (uint64_t)number;
			} else {
				value = longs ? va_arg(arguments, unsigned long long) : va_arg(arguments, unsigned int);
			}
			const char *digits = c == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
			unsigned base = c == 'x' || c == 'X' ? 16 : 10, count = 0;
			char reversed[24];
			do {
				reversed[count++] = digits[value % base];
				value /= base;
			} while (value != 0);
			/* The sign goes before zeros, but after spaces */
			if (negative && zero)
				VITALS_LOG_PUT('-');
			for (unsigned pad = count + (unsigned)negative; pad < width; ++pad)
				VITALS_LOG_PUT(zero ? '0' : ' ');
			if (negative && !zero)
				VITALS_LOG_PUT('-');
			while (count != 0)
				VITALS_LOG_PUT(reversed[--count]);
		}
	}
#undef VITALS_LOG_PUT
	if (size != 0)
		out[used] = '\0';
	return used;
}

#endif
