/*
 * vncproxy
 *
 * (c) 2011 Flexiant Limited
 *
 */

#ifndef _GAUCTEST_UTILS_H
#define _GAUCTEST_UTILS_H

typedef struct debugblock
{
  char *targetname;
  int loglevel;
  struct debugblock *next;
  struct debugblock *prev;
} debugblock_t;

/* Note this is a separate static variable per file */
static struct debugblock *pfiledebugblock = NULL;	/* NB - per file variable */

int processdebugoptions (char *options);
void dolog_internal (struct debugblock *db, int priority, const char *fmt,
		     ...);
int shouldlog (int priority);
void startsyslog ();
void stopsyslog ();
int timeval_subtract (struct timeval *result, struct timeval *x,
		      struct timeval *y);
void gettimeout (struct timespec *ts, int seconds);
void gettimeoutms (struct timespec *ts, int ms);
int safesystem (char *command, char *const cargv[], int *status,
		char *pipedata);
void fd_add_with_max (int fd, int *max, fd_set * fds);
int delete_directory_recursive (char *path);
int ensure_directory (char *path, mode_t mode);
int ensure_directory_recursive (char *path, mode_t mode, int final);
int testdirwriteable (const char *dir);
struct debugblock *adddebugblock (struct debugblock *db);
int writememtofileatomic (void *mem, size_t count, char *fn);
uint64_t getsize (char *arg);
int memcmpzero (const void *s, size_t n);
int tcp_listen_connection (int port);
int unix_listen_connection (char *path);

#define DEBUGFILE							\
  static struct debugblock filedebugblock =				\
    { __FILE__, LOG_NOTICE, NULL, NULL };				\
  __attribute__ ((__constructor__))					\
  static void								\
  addfiledebugblock()							\
  {									\
    pfiledebugblock = adddebugblock(&filedebugblock);			\
  }									\

#define DEBUGBLOCK(d)							\
  static struct debugblock_ ## d= { d, LOG_NOTICE, 0, NULL, NULL};	\
  __attribute__ ((__constructor__))					\
  void									\
  adddebugblock_ ## d ()						\
  {									\
    adddebugblock(&debugblock_ ## d);					\
  }									\

#define shouldlogdb(db, priority) (db && (db->loglevel >= priority))

#define shouldlog(priority) (shouldlogdb(pfiledebugblock, priority))

#define dologdb(db, priority, fmt...)					\
  do									\
    {									\
      if (shouldlog(&(debugblock_ ## db)))				\
	dolog_internal(&(debugblock ## db), priority, ## fmt );		\
    } while (0)

#define dolog(priority, fmt...)						\
  do									\
    {									\
      if (shouldlog(priority))						\
	dolog_internal(pfiledebugblock, priority, ## fmt );		\
    } while (0)


static inline uint64_t
htonll (uint64_t x)
{
#ifdef WORDS_BIGENDIAN
  return x;
#else
  return (((uint64_t) (htonl (((uint32_t *) & x)[0]))) << 32) |
    (uint64_t) (htonl (((uint32_t *) & x)[1]));
#endif
}

#define ntohll htonll

static inline uint64_t
gettimeofdayus ()
{
  struct timeval tv = { 0, 0 };
  gettimeofday (&tv, NULL);
  return ((uint64_t) (tv.tv_sec)) * 1000000ULL + (uint64_t) (tv.tv_usec);
}

#ifdef DEBUG_COND_WAIT
static inline int
pthread_cond_timedwait_dd (pthread_cond_t * cond, pthread_mutex_t * mutex,
			   const struct timespec *abstime,
			   const char *condvar, const char *file,
			   const int line, const char *func)
{
  struct timeval start;
  struct timeval stop;
  struct timeval diff;
  int ret;
  dolog (LOG_DEBUG,
	 "[%08x] pthread_cond_timedwait_d(%s) in %s, abstime=(%d.%09d) at %s:%d starting",
	 (int) pthread_self (), condvar, func, abstime->tv_sec,
	 abstime->tv_nsec, file, line);
  gettimeofday (&start, NULL);
  ret = pthread_cond_timedwait (cond, mutex, abstime);
  gettimeofday (&stop, NULL);
  timeval_subtract (&diff, &stop, &start);
  dolog (LOG_DEBUG,
	 "[%08x] pthread_cond_timedwait_d(%s) in %s, at %s:%d took %d.%06d seconds, and returned %s",
	 (int) pthread_self (), condvar, func, file, line, diff.tv_sec,
	 diff.tv_usec, ret ? strerror (ret) : "[no error]");
  return ret;
}

static inline int
pthread_cond_broadcast_dd (pthread_cond_t * cond,
			   const char *condvar, const char *file,
			   const int line, const char *func)
{
  struct timeval start;
  struct timeval stop;
  struct timeval diff;
  int ret;
  gettimeofday (&start, NULL);
  ret = pthread_cond_broadcast (cond);
  gettimeofday (&stop, NULL);
  timeval_subtract (&diff, &stop, &start);
  dolog (LOG_DEBUG,
	 "[%08x] pthread_cond_broadcast_d(%s) in %s, at %s:%d took %d.%06d seconds, and returned %s",
	 (int) pthread_self (), condvar, func, file, line, diff.tv_sec,
	 diff.tv_usec, ret ? strerror (ret) : "[no error]");
  return ret;
}

#define pthread_cond_timedwait_d(x,y,z) pthread_cond_timedwait_dd(x,y,z,#x,__FILE__,__LINE__,__FUNCTION__)
#define pthread_cond_broadcast_d(x) pthread_cond_broadcast_dd(x,#x,__FILE__,__LINE__,__FUNCTION__)

#else
#define pthread_cond_timedwait_d pthread_cond_timedwait
#define pthread_cond_broadcast_d pthread_cond_broadcast
#endif

static inline void *
pagealign (void *a, uintptr_t s)
{
  return (void *) ((uintptr_t) a & ~(s - 1));
}


#endif /* #ifndef _GAUCTEST_UTILS_H */
