/*
 * vncproxy
 *
 * (c) 2011 Flexiant Limited
 *
 */

#include "guactest.h"
#include "utils.h"
#include "list.h"

DEBUGFILE;
DECLARE_LIST (debugblock_t);
DEFINE_LIST (debugblock_t);

debugblock_t_list_t debugblocklist;

char *progname = "vncproxy";
int logtosyslog = 0;
int dontdaemonize = 1;

pthread_mutex_t logmutex = PTHREAD_MUTEX_INITIALIZER;

struct debugblock *
adddebugblock (struct debugblock *db)
{
  debugblock_t_list_addtail (&debugblocklist, db);

  return db;
}

static int
strdotcmp (const char *s1, const char *s2)
{
  char c1;
  char c2;
  do
    {
      c1 = *s1++;
      if (c1 == '.')
	c1 = 0;
      c2 = *s2++;
      if (c2 == '.')
	c2 = 0;
      if (c1 != c2)
	return -1;
    }
  while (c1 && c2);
  return 0;
}

static const char *debuglevels[] = {
  "EMERG",
  "ALERT",
  "CRIT",
  "ERR",
  "WARNING",
  "NOTICE",
  "INFO",
  "DEBUG",
  NULL
};

static int
stringtolevel (const char *s)
{
  int l;
  for (l = 0; debuglevels[l]; l++)
    if (!strcasecmp (s, debuglevels[l]))
      return l;
  return atoi (s);
}

int
processdebugoptions (char *options)
{
  char *saveptr = NULL;
  char *delims = ",;";
  char *opt = NULL;
  char *optionsdup = strdup (options);
  int defaultlevel = LOG_DEBUG;
  struct debugblock *db;

  /* Set all log levels to -1 */
  for (db = debugblock_t_list_gethead (&debugblocklist); db; db = db->next)
    db->loglevel = -1;

  /*  while (NULL != (opt = strtok_r (opt?NULL:options, delims, &saveptr))) */
  while (NULL != (opt = strtok_r (opt ? NULL : optionsdup, delims, &saveptr)))
    {
      char *equals = strchr (opt, '=');
      if (equals)
	{
	  *equals = 0;
	  for (db = debugblock_t_list_gethead (&debugblocklist); db;
	       db = db->next)
	    if (!strdotcmp (opt, db->targetname))
	      {
		db->loglevel = stringtolevel (equals + 1);	/* at worst the original NULL */
		*equals = '=';
		/* do not break; as we may have several of these due to
		   the same debug block in several files */
	      }
	  if (!*equals)
	    {
	      fprintf (stderr, "Unknown debug target: %s\n", opt);
	      free (optionsdup);
	      return -1;
	    }
	}
      else
	defaultlevel = stringtolevel (opt);
    }

  for (db = debugblock_t_list_gethead (&debugblocklist); db; db = db->next)
    if (db->loglevel == -1)
      {
	db->loglevel = defaultlevel;
      }

  free (optionsdup);
  return 0;
}

/* Log function */

void
dolog_internal (struct debugblock *db, int priority, const char *fmt, ...)
{
#define MAXMESSAGE 2048
#define TRUNCATION "...[truncated]"
  va_list ap;
  char message[MAXMESSAGE + sizeof (TRUNCATION) + 1];
  struct timeval tv;
  struct tm tm;
  char tstring[256];

  message[0] = '\0';
  va_start (ap, fmt);
  vsnprintf (message, MAXMESSAGE, fmt, ap);
  va_end (ap);

  /* allow the string to flow through to our truncation message */
  message[MAXMESSAGE - 1] = ' ';
  strcpy (message + MAXMESSAGE, TRUNCATION);

  pthread_mutex_lock (&logmutex);

  if (logtosyslog)
    {
      syslog (priority, "%s: %s", db->targetname, message);
      pthread_mutex_unlock (&logmutex);
      return;
    }

  /* Do something different if daemonized here */

  gettimeofday (&tv, NULL);
  localtime_r (&tv.tv_sec, &tm);
  strftime (tstring, sizeof (tstring), "%Y-%m-%d %H:%M:%S", &tm);
  fprintf (stderr, "%s.%06d ", tstring, (int) tv.tv_usec);

  fprintf (stderr, "%s: %s", db->targetname, message);
  if (*message)
    {
      if (message[strlen (message) - 1] != '\n')
	fputc ('\n', stderr);
    }

  pthread_mutex_unlock (&logmutex);

}

void
startsyslog ()
{
  if (!dontdaemonize)
    {
      openlog (progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
      logtosyslog = 1;
    }
}

void
stopsyslog ()
{
  if (logtosyslog)
    {
      closelog ();
      logtosyslog = 0;
    }
}

int
timeval_subtract (struct timeval *result, struct timeval *x,
		  struct timeval *y)
{
  if (x->tv_usec < y->tv_usec)
    {
      int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
      y->tv_usec -= 1000000 * nsec;
      y->tv_sec += nsec;
    }

  if (x->tv_usec - y->tv_usec > 1000000)
    {
      int nsec = (x->tv_usec - y->tv_usec) / 1000000;
      y->tv_usec += 1000000 * nsec;
      y->tv_sec -= nsec;
    }

  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  return x->tv_sec < y->tv_sec;
}

void
gettimeout (struct timespec *ts, int seconds)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  ts->tv_sec = now.tv_sec + seconds;
  ts->tv_nsec = now.tv_usec * 1000;
}

void
gettimeoutms (struct timespec *ts, int ms)
{
  struct timeval now;
  gettimeofday (&now, NULL);
  ts->tv_sec = now.tv_sec;
  ts->tv_nsec = now.tv_usec * 1000LL + ms * 1000000LL;
  while (ts->tv_nsec >= 1000000000L)
    {
      ts->tv_sec++;
      ts->tv_nsec -= 1000000000L;
    }
}

/*
 * This is a safe implementaton of the system() function
 */
int
safesystem (char *command, char *const cargv[], int *status, char *pipedata)
{
  sigset_t set;
  struct sigaction sa;
  int pipefd[2] = { -1, -1 };

  const char *devnull = "/dev/null";

  if (pipedata)
    {
      if (pipe (pipefd) == -1)
	{
	  dolog (LOG_ERR, "Critical: pipe() error\n");
	  return -1;
	}
    }

  int i = fork ();
  if (i < 0)
    {
      dolog (LOG_ERR, "Critical: fork() error\n");
      if (pipedata)
	{
	  close (pipefd[0]);
	  close (pipefd[1]);
	}
      return -1;
    }

  if (i > 0)
    {
      /* We are the parent */
      if (pipedata)
	{
	  close (pipefd[0]);	/* close read end of pipe */

	  /* do the write */
	  write (pipefd[1], pipedata, strlen (pipedata));
	  close (pipefd[1]);
	}
      waitpid (i, status, 0);
      /* ignore the result, restore the signal handler */
      return 0;
    }

  setsid ();
  chdir ("/");

  for (i = 0; cargv[i]; i++)
    dolog (LOG_DEBUG, "Parameter %s", cargv[i]);

  if (pipedata)
    dolog (LOG_DEBUG, "STDIN = %s", pipedata);

  for (i = getdtablesize () - 1; i >= 0; i--)
    {
      if (!pipedata || (i != pipefd[0]))
	close (i);
    }

  i = open (devnull, O_RDWR);
  if (i == -1)
    {
      fprintf (stderr, "Unable to open /dev/null\n");
      _exit (1);
    }

  if (pipedata)
    {
      dup2 (pipefd[0], 0);
    }
  else
    {
      i = open (devnull, O_RDONLY);
      if (i != 0)
	{
	  dup2 (i, 0);
	  close (i);
	}
    }

  i = open (devnull, O_WRONLY);
  if (i != 1)
    {
      dup2 (i, 1);
      close (i);
    }

  i = open (devnull, O_WRONLY);
  if (i != 2)
    {
      dup2 (i, 2);
      close (i);
    }

  /* Set up the structure to specify the new action. */
  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = SIG_DFL;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGPIPE, &sa, NULL);
  sigaction (SIGCHLD, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);
  sigaction (SIGUSR1, &sa, NULL);
  sigaction (SIGUSR2, &sa, NULL);

  /* unblock all signals */
  sigfillset (&set);
  pthread_sigmask (SIG_UNBLOCK, &set, NULL);


  execv (command, cargv);
  _exit (1);
  return -1;			/* never reached */
}

void
fd_add_with_max (int fd, int *max, fd_set * fds)
{
  if ((fd < 0) || !max || !fds)
    return;
  FD_SET (fd, fds);
  if (fd > *max)
    *max = fd;
  return;
}

int
delete_directory_recursive_fn (const char *fpath, const struct stat *sb,
			       int typeflag, struct FTW *ftwbuf)
{
  return (typeflag == FTW_D) ? rmdir (fpath) : unlink (fpath);
}

int
delete_directory_recursive (char *path)
{
  return nftw (path, &delete_directory_recursive_fn, 10,
	       FTW_DEPTH | FTW_PHYS);
}


int
ensure_directory (char *path, mode_t mode)
{
  struct stat s;
  int ret;
  ret = stat (path, &s);
  if (ret < 0)
    {
      if (errno == ENOENT)
	return mkdir (path, mode);
      else
	return -1;
    }

  if (S_ISDIR (s.st_mode))
    return 0;

  errno = EEXIST;
  return -1;
}

/*
 * This does roughly the equivalent of mkdir -p, i.e. ensures the path
 * to a directory exists. If final is set, then the path itself is a directory
 * else it the path is an object that is to be stored in the directory
 */
int
ensure_directory_recursive (char *path, mode_t mode, int final)
{
  char *start;
  char *pdup;
  char *slash;

  /* make a copy of path as we are to modify it */
  pdup = strdup (path);
  if (!pdup)
    {
      errno = ENOMEM;
      return -1;
    }

  start = pdup;


  while (1)
    {
      slash = strchr (start, '/');
      if (!slash)
	{
	  /* we are on the last component */
	  free (pdup);
	  if (final)
	    return ensure_directory (path, mode);
	  else
	    return 0;
	}
      if (slash != pdup)
	{
	  *slash = 0;
	  if (ensure_directory (pdup, mode) < 0)
	    {
	      free (pdup);
	      return -1;
	    }
	  *slash = '/';
	}
      start = slash + 1;
    }
  return -1;			/* not reached */
}

int
testdirwriteable (const char *dir)
{
  char *fn;
  int fd;
  if (asprintf (&fn, "%s/.test", dir) < 0)
    {
      errno = ENOMEM;
      return -1;
    }

  if ((fd = open (fn, O_CREAT | O_RDWR, 0644)) < 0)
    {
      free (fn);
      return -1;
    }

  close (fd);
  if (unlink (fn) < 0)
    {
      free (fn);
      return -1;
    }

  free (fn);
  return 0;
}

int
writememtofileatomic (void *mem, size_t count, char *fn)
{
  char *tempfn;
  int fd;
  if (-1 == (asprintf (&tempfn, "%s%s", fn, ".tmp")))
    {
      dolog (LOG_CRIT, "Could not allocate temporary file name");
      return -1;
    }

  if ((fd = open (tempfn, O_RDWR | O_CREAT, 0644)) == -1)
    {
      dolog (LOG_CRIT, "Could not open file to write: %m");
      free (tempfn);
      return -1;
    }

  if (write (fd, mem, count) < 0)
    {
      dolog (LOG_CRIT, "Could not write: %m");
      close (fd);
      free (tempfn);
      return -1;
    }

  close (fd);

  if (rename (tempfn, fn) < 0)
    {
      dolog (LOG_CRIT, "Could not rename: %m");
      free (tempfn);
      return -1;
    }

  free (tempfn);
  return 0;
}

uint64_t
getsize (char *arg)
{
  uint64_t param = 0;
  char *end, *found;
  const char *suffix = "bkmgtpe";
  param = strtoull (arg, &end, 10);

  if (*end == '\0')
    {
      /* param is right - do nothing */
    }
  else if ((found = strchr (suffix, tolower (*end))))
    {
      param <<= (10 * (found - suffix));
    }
  else
    {
      dolog (LOG_CRIT, "Bad parameter\n");
      exit (1);
    }
  return param;
}

/* Like memcmp, returns 0 if a block of memory is zero */
int
memcmpzero (const void *s, size_t n)
{
  const char *cp;
  const uint64_t *up;

  /* first align to 8 byte boundary */
  for (cp = s; (n > 0) && (((uintptr_t) cp) & 7); n--)
    {
      if (*(cp++))
	return 1;
    }

  /* Now work 8 bytes at a time */
  for (up = (uint64_t *) cp; (n >= 8); n -= 8)
    {
      if (*(up++))
	return 1;
    }

  /* Now check the remaining stuff byte by byte */
  for (cp = (char *) up; n > 0; n--)
    {
      if (*(cp++))
	return 1;
    }

  return 0;
}

/* Initialise the listen socket for connections, return the fd  */
int
tcp_listen_connection (int port)
{
  int listenfd;
  struct sockaddr_in listenaddr;
  int one = 1;

  if (-1 == (listenfd = socket (AF_INET, SOCK_STREAM, 0)))
    {
      dolog (LOG_CRIT, "open() Could not create listen socket");
      return -1;
    }

  if (-1 ==
      setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)))
    {
      dolog (LOG_CRIT, "open() Could not do SO_REUSEADDR");
      close (listenfd);
      return -1;
    }

  /* Zero out socket data, then set it up */
  memset (&listenaddr, 0, sizeof (listenaddr));
  listenaddr.sin_family = AF_INET;
  listenaddr.sin_addr.s_addr = htonl (INADDR_ANY);
  listenaddr.sin_port = htons (port);

  if (-1 ==
      bind (listenfd, (struct sockaddr *) &listenaddr, sizeof (listenaddr)))
    {
      dolog (LOG_CRIT, "open() Could not bind listen socket");
      close (listenfd);
      return -1;
    }

  if (-1 == listen (listenfd, 100))
    {
      dolog (LOG_CRIT, "open() Could not listen on listen socket");
      close (listenfd);
      return -1;
    }

  return listenfd;
}

/* Initialise the listen socket for connections, return the fd  */
int
unix_listen_connection (char *path)
{
  int listenfd;
  struct sockaddr_un *listenaddr;
  int len;
  len = sizeof (sa_family_t) + strlen (path) + 1;

  if (NULL == (listenaddr = calloc (1, len)))
    {
      dolog (LOG_CRIT, "could not allocate the listen socket");
      exit (1);
    }

  unlink (path);		/* ignore errors */

  if (-1 == (listenfd = socket (AF_UNIX, SOCK_STREAM, 0)))
    {
      dolog (LOG_CRIT, "open() Could not create listen socket");
      free (listenaddr);
      return -1;
    }

  /* Zero out socket data, then set it up */
  listenaddr->sun_family = AF_UNIX;
  strcpy (listenaddr->sun_path, path);	/* length checked on allocation */

  if (-1 == bind (listenfd, (struct sockaddr *) listenaddr, len))
    {
      dolog (LOG_CRIT, "open() Could not bind listen socket");
      free (listenaddr);
      close (listenfd);
      return -1;
    }

  free (listenaddr);

  if (-1 == listen (listenfd, 100))
    {
      dolog (LOG_CRIT, "open() Could not listen on listen socket");
      close (listenfd);
      return -1;
    }

  return listenfd;
}
