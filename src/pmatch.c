
int pmatch(const char *p, const char *s, unsigned int len) {
  for (;;) {
    char c =*p++;
    if (! c) return(! len);
    switch(c) {
    case '*':
      if (! (c =*p)) return(1);
      for (;;) {
        if (! len) return(0);
        if (*s == c) break;
        ++s; --len;
      }
      continue;
    case '+':
      if ((c =*p++) != *s) return(0);
      for (;;) {
        if (! len) return(1);
        if (*s != c) break;
        ++s; --len;
      }
      continue;
      /*
    case '?':
      if (*p == '?') {
        if (*s != '?') return(0);
        ++p;
      }
      ++s; --len;
      continue;
      */
    default:
      if (! len) return(0);
      if (*s != c) return(0);
      ++s; --len;
      continue;
    }
  }
  return(0);
}
