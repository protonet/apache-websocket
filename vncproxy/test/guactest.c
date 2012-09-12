/*
 * vncproxy
 *
 * (c) 2011 Flexiant Limited
 *
 */

#include "guactest.h"
#include "list.h"
#include "utils.h"

DEBUGFILE;

typedef struct gtconnection
{
  int wsproxyfd;
  int doneinit;
  int packet;
  int needsync;
  int sendsync;
  int lastsynctx;
  int lastsyncrx;
  ssize_t offset;
  struct timeval lastsynctime;
  struct timeval activetime;
  struct gtconnection *prev;
  struct gtconnection *next;
} gtconnection_t;

DECLARE_LIST (gtconnection_t);
DEFINE_LIST (gtconnection_t);

/* Set by the signal handler */
volatile sig_atomic_t master_rxsig_quit = 0;
volatile sig_atomic_t master_rxsig_reread = 0;
volatile sig_atomic_t master_rxsig_process = 0;
volatile sig_atomic_t master_rxsig_pipe = 0;

int listenport = 4823;
int timeout = 30;

#define DATALENGTH 65536
#define MAXCMDLENGTH 128

char * initialdata = "5.reset,1.0;4.size,1.0,4.1024,3.768;5.reset,1.0;";
char * subsequentdata = NULL;

gtconnection_t_list_t gtconnectionlist;

int
plen(int v)
{
  int k;
  int j=10;
  if (v<0)
    return 1+plen(-v);
  for (k=1;;k++,j*=10)
    if (v<j)
      return k;
}

void
makedata()
{
  char * p;
  int space;
  for (p = subsequentdata; (space = subsequentdata + DATALENGTH - p, space > MAXCMDLENGTH); )
    {
      int x=random() % 1024;
      int y=random() % 768;
      int w=1+random() % 512;
      int h=1+random() % 384;
      int r=random() % 256;
      int g=random() % 256;
      int b=random() % 256;
      int a=random() % 256;
      p+=snprintf(p, space, "4.rect,1.0,%d.%d,%d.%d,%d.%d,%d.%d;",
		  plen(x),x,
		  plen(y),y,
		  plen(w),w,
		  plen(h),h);
      p+=snprintf(p, space, "5.cfill,1.0,1.0,%d.%d,%d.%d,%d.%d,%d.%d;",
		  plen(r),r,
		  plen(g),g,
		  plen(b),b,
		  plen(a),a);
    }
}

gtconnection_t *
gtconnection_new ()
{
  gtconnection_t *gc = calloc (1, sizeof (struct gtconnection));
  if (!gc)
    return NULL;
  gc->wsproxyfd = -1;
  gc->offset = 0;
  return gc;
}

void
gtconnection_free (gtconnection_t * gc)
{
  /* first dump the buffers */
  dolog (LOG_DEBUG, "gtconnection_free: called");

  free (gc);
  return;
}

int
gtconnection_close (gtconnection_t * gc)
{
  if (gc->wsproxyfd >= 0)
    {
      shutdown (gc->wsproxyfd, SHUT_RDWR);
      close (gc->wsproxyfd);
      gc->wsproxyfd = -1;
    }
  return 0;
}

void
gtconnection_delete (gtconnection_t * gc)
{
  gtconnection_close (gc);
  gtconnection_free (gc);
}

void
gtconnection_accept (int listenfd)
{
  struct sockaddr_in saddr;
  socklen_t salen = sizeof (saddr);	/* not large enough for unix domain sockets but that's OK */
  struct gtconnection *mc = NULL;
  int fd;

  if (listenfd < 0)
    return;

  if (-1 == (fd = accept (listenfd, (struct sockaddr *) &saddr, &salen)))
    {
      dolog (LOG_ERR, "Master: Could not accept a new connection");
      /* This might have been that the connection has disappeared before we got here, but
       * there is a risk of a busy-loop here so sleep
       */
      usleep (1000);
      return;
    }

  int flags = -1;
  if (-1 == (flags = fcntl (fd, F_GETFL, 0)))
    {
      dolog (LOG_ERR, "gtconnection_accept: fcntl F_GETFL failed");
      close (fd);
      return;
    }

  if (-1 == fcntl (fd, F_SETFL, flags | O_NONBLOCK))
    {
      dolog (LOG_ERR, "gtconnection_accept: fcntl F_SETFL failed");
      close (fd);
      return;
    }

  if (NULL == (mc = gtconnection_new ()))
    {
      dolog (LOG_ERR,
	     "gtconnection_accept: Could not allocate a new connection");
      close (fd);
      return;
    }

  mc->wsproxyfd = fd;
  gettimeofday (&(mc->activetime), NULL);
  gettimeofday (&(mc->lastsynctime), NULL);

  gtconnection_t_list_addtail (&gtconnectionlist, mc);
  return;
}

void
handlesignal (int sig)
{
  /* DO NOT dolog() in here as the logging mutex may already be held */
  switch (sig)
    {
    case SIGINT:
    case SIGTERM:
      master_rxsig_quit++;
      break;
    case SIGHUP:
      master_rxsig_reread++;
      break;
    case SIGCHLD:
      /* do all our waiting here */
      while (1)
	{
	  pid_t pid;
	  int status;
	  pid = waitpid (WAIT_ANY, &status, WNOHANG);
	  if (pid < 0)
	    {
	      break;
	    }
	  if (pid == 0)
	    break;
	  /* pid has terminated */
	}
      break;
    case SIGPIPE:
      master_rxsig_pipe++;
      break;
    default:
      break;
    }
}

int
domasterselectsignals ()
{
  /* process signals */
  if (master_rxsig_pipe)
    {
      dolog (LOG_DEBUG, "SIGPIPE received");
      master_rxsig_pipe = 0;
    }
  if (master_rxsig_reread)
    {
      master_rxsig_reread = 0;
      /* configreread (); */
    }
  return (master_rxsig_quit);
}


void
mastermainloop ()
{
  fd_set readfds;
  fd_set writefds;
  struct timeval lastread;
  struct timeval now;
  struct timeval elapsed;
  sigset_t set;
  struct sigaction sa;
  int masterlistentcpfd = -1;

  gettimeofday (&lastread, NULL);

  if (-1 == (masterlistentcpfd = tcp_listen_connection (listenport)))
    {
      perror ("Could not listen on tcp master port");
      exit (1);
    }

  int flags = -1;
  if (-1 == (flags = fcntl (masterlistentcpfd, F_GETFL, 0)))
    {
      close (masterlistentcpfd);
      dolog (LOG_ERR, "fcntl F_GETFL failed");
      exit (1);
    }

  if (-1 == fcntl (masterlistentcpfd, F_SETFL, flags | O_NONBLOCK))
    {
      close (masterlistentcpfd);
      dolog (LOG_ERR, "fcntl F_SETFL failed");
      exit (1);
    }

  /* block all signals */
  sigfillset (&set);
  pthread_sigmask (SIG_BLOCK, &set, NULL);

  /* Set up the structure to specify the new action. */
  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = handlesignal;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGPIPE, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);
  sigaction (SIGUSR1, &sa, NULL);
  sigaction (SIGUSR2, &sa, NULL);
  sigaction (SIGCHLD, &sa, NULL);

  sigemptyset (&set);
  sigaddset (&set, SIGINT);
  sigaddset (&set, SIGTERM);
  sigaddset (&set, SIGPIPE);
  sigaddset (&set, SIGHUP);
  sigaddset (&set, SIGUSR1);
  sigaddset (&set, SIGUSR2);
  sigaddset (&set, SIGCHLD);
  pthread_sigmask (SIG_UNBLOCK, &set, NULL);

  master_rxsig_quit = 0;

  do
    {
      master_rxsig_pipe = 0;

      do
	{
	  int maxfd = 0;
	  int periodic = 0;
	  int quit = 0;
	  int result = 0;
	  int selecterrno = 0;
	  struct gtconnection *mc = NULL;
	  struct gtconnection *nmc = NULL;

	  FD_ZERO (&readfds);
	  FD_ZERO (&writefds);

	  /* Leave 10 fds spare for logging etc */
	  if (gtconnection_t_list_getitems (&gtconnectionlist) * 2 <
	      FD_SETSIZE - 10)
	    fd_add_with_max (masterlistentcpfd, &maxfd, &readfds);

	  gettimeofday (&now, NULL);
	  for (mc = gtconnection_t_list_gethead (&gtconnectionlist); mc;
	       mc = mc->next)
	    {
	      /* Now communication between the VM and Wsproxy */
	      if (mc->wsproxyfd >= 0)
		{
		  if (!timeval_subtract (&elapsed, &now, &(mc->lastsynctime))
		      && (elapsed.tv_sec >= 2))
		    mc->lastsyncrx = mc->lastsynctx;

		  if (mc->lastsynctx > mc->lastsyncrx)
		    dolog(LOG_DEBUG, "Waiting as lastsynctx = %d lastsyncrx = %d",
			  mc->lastsynctx,
			  mc->lastsyncrx);
		  else
		    fd_add_with_max (mc->wsproxyfd, &maxfd, &writefds);
		  fd_add_with_max (mc->wsproxyfd, &maxfd, &readfds);
		}
	    }

	  /* Repeat select whilst EINTR happens */
	  do
	    {
	      struct timeval timeout;
	      timeout.tv_sec = 1;
	      timeout.tv_usec = 0;
	      result =
		select (1 + maxfd, &readfds, &writefds, NULL, &timeout);

	      selecterrno = errno;

	      /* process signals */
	      quit = domasterselectsignals ();
	    }
	  while ((result == -1) && (selecterrno == EINTR) && !quit);

	  if (!quit)
	    {
	      struct timeval now;
	      struct timeval elapsed;
	      /* if more than one second has passed, do periodic jobs */
	      gettimeofday (&now, NULL);
	      if (!timeval_subtract (&elapsed, &now, &lastread)
		  && (elapsed.tv_sec >= 1))
		{
		  lastread = now;
		  periodic = 1;
		}
	    }

	  if (master_rxsig_quit)
	    break;

	  /* Process new connections */
	  if (FD_ISSET (masterlistentcpfd, &readfds))
	    {
	      gtconnection_accept (masterlistentcpfd);
	    }

	  gettimeofday (&now, NULL);
	  for (mc = gtconnection_t_list_gethead (&gtconnectionlist); mc;
	       mc = nmc)
	    {
	      nmc = mc->next;

	      if ((mc->wsproxyfd >= 0) && FD_ISSET (mc->wsproxyfd, &readfds))
		{
		  char buf[1025];
		  buf[1024]=0;
		  gettimeofday (&(mc->activetime), NULL);
		  ssize_t got = 0;
		  if ((got = read (mc->wsproxyfd, buf, sizeof(buf)-1))<=0)
		    {
		      dolog (LOG_DEBUG,
			     "Read from fd returned 0 bytes, closing connection");
		      gtconnection_t_list_unlink (&gtconnectionlist, mc);
		      gtconnection_delete (mc);
		      continue;
		    }
		  buf[got]=0;
		  char * s = buf;
		  if (NULL != (s = strstr(buf,"sync")))
		    {
		      char * p;
		      for (p = s; *p && (*p != ';'); p++) {}
		      *p=0;
		      p = s+5;
		      while (*p && (*p != '.'))
			p++;
		      p++;
		      mc->lastsyncrx = atoi(p);
		      dolog (LOG_DEBUG, "Got %s lastsyncrx=%d p=%s", s, mc->lastsyncrx, p);
		      mc->needsync=0;
		    }
		  dolog (LOG_DEBUG, "Got '%s'", buf);
		}

	      if ((mc->wsproxyfd >= 0) && FD_ISSET (mc->wsproxyfd, &writefds))
		{
		  gettimeofday (&(mc->activetime), NULL);
		  char syncbuf[20];
		  snprintf(syncbuf, 20, "4.sync,%d.%d;", plen(mc->lastsynctx+1), mc->lastsynctx+1);
		  mc->packet++;
		  char * buf = (mc->sendsync)?syncbuf:((mc->doneinit)?subsequentdata:initialdata);
		  ssize_t len = strlen(buf);
		  if (mc->sendsync)
		    {
		      dolog (LOG_DEBUG,
			     "writing sync %s", buf);
		      mc->lastsynctx++;
		    }
		  ssize_t written = -1;
		  ssize_t towrite = len - mc->offset;
		  if ((written = write(mc->wsproxyfd, buf + mc->offset, towrite))<0)
		    {
		      dolog (LOG_DEBUG,
			     "vncbuf_writetofd to websocket returned error, closing connection");
		      gtconnection_t_list_unlink (&gtconnectionlist, mc);
		      gtconnection_delete (mc);
		      continue;
		    }
		  mc->offset += written;
		  if (mc->offset >= len)
		    {
		      dolog (LOG_DEBUG, "Wrapping");
		      mc->offset = 0;
		      mc->doneinit = 1;
		      if (mc->sendsync)
			{
			  gettimeofday (&(mc->lastsynctime), NULL);
			  makedata();
			}
		      mc->needsync = mc->sendsync;
		      mc->sendsync = !(mc->sendsync);
		    }
		}

	      if (!timeval_subtract (&elapsed, &now, &(mc->activetime))
		  && (elapsed.tv_sec >= timeout))
		{
		  dolog (LOG_INFO,
			 "mastermainloop: connection idle too long");
		  gtconnection_t_list_unlink (&gtconnectionlist, mc);
		  gtconnection_delete (mc);
		}
	    }

	}
      while (!master_rxsig_quit);

      /* Do deinit here for stuff where we need a cf file reread */

    }
  while (!master_rxsig_quit);

  if (masterlistentcpfd != -1)
    {
      close (masterlistentcpfd);
      masterlistentcpfd = -1;
    }
}


int
main (int argc, char **argv)
{
  processdebugoptions("7");

  startsyslog ();

  dolog (LOG_NOTICE, "Starting up");

  subsequentdata = calloc (1, DATALENGTH+MAXCMDLENGTH+1);
  makedata();

  mastermainloop ();

  dolog (LOG_NOTICE, "Exiting\n");

  fflush (stdout);
  fflush (stderr);

  exit (0);
}
