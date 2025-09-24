/* Kept for backward compatibility with older builds.
   This project no longer uses stb_sprintf; you can delete this file if you want. */

/* Original header below (truncated intentionally to avoid unused code warnings).
   If you need stb_sprintf again, fetch the latest from:
   https://github.com/nothings/stb/blob/master/stb_sprintf.h
*/
#ifndef STB_SPRINTF_H_INCLUDE
#define STB_SPRINTF_H_INCLUDE
#include <stdarg.h>
#ifdef __cplusplus
extern "C" {
#endif
int stbsp_sprintf(char *buf, char const *fmt, ...);
int stbsp_snprintf(char *buf, int count, char const *fmt, ...);
int stbsp_vsprintf(char *buf, char const *fmt, va_list va);
int stbsp_vsnprintf(char *buf, int count, char const *fmt, va_list va);
#ifdef __cplusplus
}
#endif
#endif /* STB_SPRINTF_H_INCLUDE */
