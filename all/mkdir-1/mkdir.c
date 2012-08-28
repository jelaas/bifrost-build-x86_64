/*
 * Almost everything copied and put together from the embutils suite of programs
 * written by Felix von Leitner.
 *
 * The license as given by Felix is: GNU GENERAL PUBLIC LICENSE, Version 2, June 1991
 *
 * This sourcecode merge and glue-code is done by: Jens Låås, UU, 2012.
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

void __write2(const char *s)
{
	write(2, s, strlen(s));
}

void __write1(const char *s)
{
	write(1, s, strlen(s));
}

static void oops(char *message) {
  __write2("mkdir: ");
  __write2(message);
  __write2("\n");
}

static void error(char *message) {
  oops(message);
  exit(1);
}


void parsemode(char *m,mode_t *and,mode_t *or) {
  int mult,val;
  int add;
  char op;

  if (*m>='0' && *m<='7') {	/* octal number */
    int mode=0;
    do {
      mode=mode*8+*m++-'0';
    } while (*m>='0' && *m<='7');
    *and=0; *or=mode;
    return;
  }
  /* [ugoa]*{+|-|=}[rwxst]* */
  *and=(mode_t)-1; *or=0;
  while (*m) {
    for (mult=0; *m>='a' && *m<='z'; m++) {
      switch (*m) {
      case 'a': mult|=0111; break;
      case 'u': mult|=0100; break;
      case 'g': mult|=0010; break;
      case 'o': mult|=0001; break;
      default: error("[augo] expected");
      }
    }
    if (mult==0) mult=0111;
    switch (*m) {
    case '+': case '-': case '=': op=*m; break;
    default: error("{+|-|=} expected");
    }
    ++m;
    for (add=val=0; *m>='a'&&*m<='z'; m++) {
      switch (*m) {
      case 'r': val|=4; break;
      case 'w': val|=2; break;
      case 'x': val|=1; break;
      case 's':
	if (mult&0100) add|=04000;
	if (mult&0010) add|=02000;
	break;
      case 't': add|=01000; break;
      default: error("[rwxst] expected");
      }
    }
    switch (op) {
    case '+': *or |= (mult*val) | add; break;
    case '-': *and &= 0xffff-((mult*val) | add); break;
    case '=': *and &= 0xffff-mult*7;
	      *or &= 0xffff-mult*7;
	      *or |= (mult*val) | add; break;
    }
    if (*m==',')
      m++;
  }
}

static int res=0;

void panic() {
  switch (errno) {
  case EPERM:
    oops("permission denied"); break;
  case EEXIST:
    oops("file exists"); break;
  case EFAULT:
    oops("invalid pointer"); break;
  case ENAMETOOLONG:
    oops("name too long"); break;
  case ENOENT:
    oops("file not found"); break;
  case ENOMEM:
    oops("out of virtual memory"); break;
  case EROFS:
    oops("read-only file system"); break;
  case EACCES:
    oops("directory search permissions denied"); break;
  case ELOOP:
    oops("too many symbolic links"); break;
  case ENOSPC:
    oops("no space left on device/quota exceeded"); break;
  case EIO:
    oops("I/O error"); break;
  default:
    oops("unknown error"); break;
  }
  res=1;
}

void domkdir(char *s,int m,int v,int iexist,char *full) {
  errno=0;
  if (*s!=0 && mkdir(s,m))
    if (!iexist || errno!=EEXIST) { panic(); return; }
  if (errno==0) {
    if (v) {
      __write2("mkdir: created directory `");
      __write2(full);
      __write2("'\n");
    }
  }
}

void minusp(char *s,int m,int v) {
  int fd=open(".",O_RDONLY);
  char *t;
  char *full=s;
  if (fd<0) { panic(); return; }
  if (*s=='/') {
    chdir("/");
    ++s;
  }
  while ((t=strchr(s,'/'))) {
    *t=0;
    domkdir(s,m,v,1,full);
    chdir(s);
    s=t+1;
    *t='/';
  }
  if (*s) domkdir(s,m,v,1,full);
  fchdir(fd);
  close(fd);
}

void usage(void) {
  __write1("Usage: mkdir [-pv] [-m mode] directory...\n"
       "  -p	no error if existing, make parent directories as needed\n"
       "  -m	set permission mode (as in chmod), not rwxrwxrwx - umask\n"
       "  -v	print a message for each created directory\n");
  exit(0);
}

int main(int argc,char *argv[]) {
  int i;
  int p=0,v=0;
  int mode=0777-umask(0);
  mode_t and,or;
  if (argc<2) usage();
  for (i=1; i<argc; i++) {
    if (!argv[i]) continue;
    if (argv[i][0]=='-') {
      int j,len=strlen(argv[i]);
      for (j=1; j<len; j++) {
	switch (argv[i][j]) {
	case '-':
	  if (!strcmp(argv[i],"--parent")) p=1;
	  else if (!strcmp(argv[i],"--verbose")) v=1;
	  else if (argv[i][2]) usage();
	  j=len; break;
	case 'p': p=1; break;
	case 'v': v=1; break;
	case 'm': parsemode(argv[i+1],&and,&or); mode=(mode&and)|or; argv[i+1]=0; break;
	default:
	  usage();
	}
      }
    } else {
      if (p) {
	minusp(argv[i],mode,v);
      } else
	domkdir(argv[i],mode,v,0,argv[i]);
    }
  }
  return res;
}

