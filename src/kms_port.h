
#if defined(_WIN32)
#define strcasecmp _stricmp


inline char *
strndup (char *src, int len)
{
   char *dst = (char *) malloc (len + 1);
   if (!dst) {
      return 0;
   }

   memcpy (dst, src, len);
   dst[len] = '\0';

   return dst;
}


#endif
