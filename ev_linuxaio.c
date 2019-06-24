/*
 * libev linux aio fd activity backend
 *
 * Copyright (c) 2019 Marc Alexander Lehmann <libev@schmorp.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifica-
 * tion, are permitted provided that the following conditions are met:
 *
 *   1.  Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *   2.  Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MER-
 * CHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPE-
 * CIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTH-
 * ERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU General Public License ("GPL") version 2 or any later version,
 * in which case the provisions of the GPL are applicable instead of
 * the above. If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the BSD license, indicate your decision
 * by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL. If you do not delete the
 * provisions above, a recipient may use your version of this file under
 * either the BSD or the GPL.
 */

#define EPOLL_FALLBACK 1

#include <sys/time.h> /* actually linux/time.h, but we must assume they are compatible */
#include <poll.h>
#include <linux/aio_abi.h>

#if EPOLL_FALLBACK
# include <sys/epoll.h>
#endif

/* we try to fill 4kB pages exactly.
 * the ring buffer header is 32 bytes, every io event is 32 bytes.
 * the kernel takes the io event number, doubles it, adds 2, adds the ring buffer.
 * therefore the calculation below will use "exactly" 4kB for the ring buffer
 */
#define EV_LINUXAIO_DEPTH (128 / 2 - 2 - 1) /* max. number of io events per batch */

/*****************************************************************************/
/* syscall wrapdadoop - this section has the raw syscall definitions */

#include <sys/syscall.h> /* no glibc wrappers */

/* aio_abi.h is not versioned in any way, so we cannot test for its existance */
#define IOCB_CMD_POLL 5

/* taken from linux/fs/aio.c */
#define AIO_RING_MAGIC                  0xa10a10a1
#define AIO_RING_INCOMPAT_FEATURES      0
struct aio_ring
{
  unsigned id;    /* kernel internal index number */
  unsigned nr;    /* number of io_events */
  unsigned head;  /* Written to by userland or by kernel. */
  unsigned tail;

  unsigned magic;
  unsigned compat_features;
  unsigned incompat_features;
  unsigned header_length;  /* size of aio_ring */

  struct io_event io_events[0];
};

inline_size
int
evsys_io_setup (unsigned nr_events, aio_context_t *ctx_idp)
{
  return syscall (SYS_io_setup, nr_events, ctx_idp);
}

inline_size
int
evsys_io_destroy (aio_context_t ctx_id)
{
  return syscall (SYS_io_destroy, ctx_id);
}

inline_size
int
evsys_io_submit (aio_context_t ctx_id, long nr, struct iocb *cbp[])
{
  return syscall (SYS_io_submit, ctx_id, nr, cbp);
}

inline_size
int
evsys_io_cancel (aio_context_t ctx_id, struct iocb *cbp, struct io_event *result)
{
  return syscall (SYS_io_cancel, ctx_id, cbp, result);
}

inline_size
int
evsys_io_getevents (aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout)
{
  return syscall (SYS_io_getevents, ctx_id, min_nr, nr, events, timeout);
}

/*****************************************************************************/
/* actual backed implementation */

/* we use out own wrapper structure in acse we ever want to do something "clever" */
typedef struct aniocb
{
  struct iocb io;
  /*int inuse;*/
} *ANIOCBP;

inline_size
void
linuxaio_array_needsize_iocbp (ANIOCBP *base, int offset, int count)
{
  while (count--)
    {
      /* TODO: quite the overhead to allocate every iocb separately, maybe use our own alocator? */
      ANIOCBP iocb = (ANIOCBP)ev_malloc (sizeof (*iocb));

      /* full zero initialise is probably not required at the moment, but
       * this is not well documented, so we better do it.
       */
      memset (iocb, 0, sizeof (*iocb));

      iocb->io.aio_lio_opcode = IOCB_CMD_POLL;
      iocb->io.aio_data       = offset;
      iocb->io.aio_fildes     = offset;

      base [offset++] = iocb;
    }
}

ecb_cold
static void
linuxaio_free_iocbp (EV_P)
{
  while (linuxaio_iocbpmax--)
    ev_free (linuxaio_iocbps [linuxaio_iocbpmax]);

  linuxaio_iocbpmax = 0; /* next resize will completely reallocate the array, at some overhead */
}

static void
linuxaio_modify (EV_P_ int fd, int oev, int nev)
{
  array_needsize (ANIOCBP, linuxaio_iocbps, linuxaio_iocbpmax, fd + 1, linuxaio_array_needsize_iocbp);
  ANIOCBP iocb = linuxaio_iocbps [fd];

#if EPOLL_FALLBACK
  if (iocb->io.aio_reqprio < 0)
    {
      epoll_ctl (backend_fd, EPOLL_CTL_DEL, fd, 0);
      iocb->io.aio_reqprio = 0;
    }
#endif

  if (iocb->io.aio_buf)
    evsys_io_cancel (linuxaio_ctx, &iocb->io, (struct io_event *)0); /* always returns an error relevant kernels */

  if (nev)
    {
      iocb->io.aio_buf =
          (nev & EV_READ ? POLLIN : 0)
          | (nev & EV_WRITE ? POLLOUT : 0);

      /* queue iocb up for io_submit */
      /* this assumes we only ever get one call per fd per loop iteration */
      ++linuxaio_submitcnt;
      array_needsize (struct iocb *, linuxaio_submits, linuxaio_submitmax, linuxaio_submitcnt, array_needsize_noinit);
      linuxaio_submits [linuxaio_submitcnt - 1] = &iocb->io;
    }
}

#if EPOLL_FALLBACK

static void
linuxaio_rearm_epoll (EV_P_ struct iocb *iocb, int op)
{
  struct epoll_event eev;

  eev.events = EPOLLONESHOT;
  if (iocb->aio_buf & POLLIN ) eev.events |= EPOLLIN ;
  if (iocb->aio_buf & POLLOUT) eev.events |= EPOLLOUT;
  eev.data.fd = iocb->aio_fildes;

  if (epoll_ctl (backend_fd, op, iocb->aio_fildes, &eev) < 0)
    ev_syserr ("(libeio) linuxaio epoll_ctl");
}

static void
linuxaio_epoll_cb (EV_P_ struct ev_io *w, int revents)
{
  struct epoll_event events[16];

  for (;;)
    {
      int idx;
      int res = epoll_wait (backend_fd, events, sizeof (events) / sizeof (events [0]), 0);

      if (expect_false (res < 0))
        ev_syserr ("(libev) linuxaio epoll_wait");
      else if (!res)
        break;

      for (idx = res; idx--; )
        {
          int      fd = events [idx].data.fd;
          uint32_t ev = events [idx].events;

          assert (("libev: iocb fd must be in-bounds", fd >= 0 && fd < anfdmax));

          linuxaio_rearm_epoll (EV_A_ &linuxaio_iocbps [fd]->io, EPOLL_CTL_MOD);

          fd_event (EV_A_ fd,
            (ev & (EPOLLOUT | EPOLLERR | EPOLLHUP) ? EV_WRITE : 0)
            | (ev & (EPOLLIN  | EPOLLERR | EPOLLHUP) ? EV_READ  : 0));
        }

      if (res < sizeof (events) / sizeof (events [0]))
        break;
    }
}

#endif

static void
linuxaio_parse_events (EV_P_ struct io_event *ev, int nr)
{
  while (nr)
    {
      int fd  = ev->data;
      int res = ev->res;

      assert (("libev: iocb fd must be in-bounds", fd >= 0 && fd < anfdmax));

      /* linux aio is oneshot: rearm fd. TODO: this does more work than needed */
      linuxaio_iocbps [fd]->io.aio_buf = 0;
      anfds [fd].events = 0;
      fd_change (EV_A_ fd, 0);

      /* feed events, we do not expect or handle POLLNVAL */
      fd_event (
        EV_A_
        fd,
        (res & (POLLOUT | POLLERR | POLLHUP) ? EV_WRITE : 0)
        | (res & (POLLIN | POLLERR | POLLHUP) ? EV_READ : 0)
      );

      --nr;
      ++ev;
    }
}

/* get any events from ringbuffer, return true if any were handled */
static int
linuxaio_get_events_from_ring (EV_P)
{
  struct aio_ring *ring = (struct aio_ring *)linuxaio_ctx;

  /* the kernel reads and writes both of these variables, */
  /* as a C extension, we assume that volatile use here */
  /* both makes reads atomic and once-only */
  unsigned head = *(volatile unsigned *)&ring->head;
  unsigned tail = *(volatile unsigned *)&ring->tail;

  if (head == tail)
    return 0;

  /* bail out if the ring buffer doesn't match the expected layout */
  if (expect_false (ring->magic != AIO_RING_MAGIC)
                    || ring->incompat_features != AIO_RING_INCOMPAT_FEATURES
                    || ring->header_length != sizeof (struct aio_ring)) /* TODO: or use it to find io_event[0]? */
    return 0;

  /* make sure the events up to tail are visible */
  ECB_MEMORY_FENCE_ACQUIRE;

  /* parse all available events, but only once, to avoid starvation */
  if (tail > head) /* normal case around */
    linuxaio_parse_events (EV_A_ ring->io_events + head, tail - head);
  else /* wrapped around */
    {
      linuxaio_parse_events (EV_A_ ring->io_events + head, ring->nr - head);
      linuxaio_parse_events (EV_A_ ring->io_events, tail);
    }

  ECB_MEMORY_FENCE_RELAXED;
  /* as an extension to C, we hope that the volatile will make this atomic and once-only */
  *(volatile unsigned *)&ring->head = tail;
  /* make sure kernel can see our new head value - probably not required */
  ECB_MEMORY_FENCE_RELEASE;

  return 1;
}

/* read at least one event from kernel, or timeout */
inline_size
void
linuxaio_get_events (EV_P_ ev_tstamp timeout)
{
  struct timespec ts;
  struct io_event ioev[1];
  int res;

  if (linuxaio_get_events_from_ring (EV_A))
    return;

  /* no events, so wait for at least one, then poll ring buffer again */
  /* this degrades to one event per loop iteration */
  /* if the ring buffer changes layout, but so be it */

  EV_RELEASE_CB;

  ts.tv_sec  = (long)timeout;
  ts.tv_nsec = (long)((timeout - ts.tv_sec) * 1e9);

  res = evsys_io_getevents (linuxaio_ctx, 1, sizeof (ioev) / sizeof (ioev [0]), ioev, &ts);

  EV_ACQUIRE_CB;

  if (res < 0)
    if (errno == EINTR)
      /* ignored */;
    else
      ev_syserr ("(libev) linuxaio io_getevents");
  else if (res)
    {
      /* at least one event received, handle it and any remaining ones in the ring buffer */
      linuxaio_parse_events (EV_A_ ioev, res);
      linuxaio_get_events_from_ring (EV_A);
    }
}

static void
linuxaio_poll (EV_P_ ev_tstamp timeout)
{
  int submitted;

  /* first phase: submit new iocbs */

  /* io_submit might return less than the requested number of iocbs */
  /* this is, afaics, only because of errors, but we go by the book and use a loop, */
  /* which allows us to pinpoint the errornous iocb */
  for (submitted = 0; submitted < linuxaio_submitcnt; )
    {
#if 0
      int res;
      if (linuxaio_submits[submitted]->aio_fildes == backend_fd)
         res = evsys_io_submit (linuxaio_ctx, 1, linuxaio_submits + submitted);
      else
        { res = -1; errno = EINVAL; };
#else
      int res = evsys_io_submit (linuxaio_ctx, linuxaio_submitcnt - submitted, linuxaio_submits + submitted);
#endif

      if (expect_false (res < 0))
        if (errno == EAGAIN)
          {
            /* This happens when the ring buffer is full, at least. I assume this means
             * that the event was queued synchronously during io_submit, and thus
             * the buffer overflowed.
             * In this case, we just try in next loop iteration.
             * This should not result in a few fds taking priority, as the interface
             * is one-shot, and we submit iocb's in a round-robin fashion.
             * TODO: maybe make "submitted" persistent, so we don't have to memmove?
             */
            if (ecb_expect_false (submitted))
              {
                memmove (linuxaio_submits, linuxaio_submits + submitted, (linuxaio_submitcnt - submitted) * sizeof (*linuxaio_submits));
                linuxaio_submitcnt -= submitted;
              }

            timeout = 0;
            break;
          }
#if EPOLL_FALLBACK
        else if (errno == EINVAL)
          {
            /* This happens for unsupported fds, officially, but in my testing,
             * also randomly happens for supported fds. We fall back to good old
             * poll() here, under the assumption that this is a very rare case.
             * See https://lore.kernel.org/patchwork/patch/1047453/ to see
             * discussion about such a case (ttys) where polling for POLLIN
             * fails but POLLIN|POLLOUT works.
             */
            struct iocb *iocb = linuxaio_submits [submitted];

            linuxaio_rearm_epoll (EV_A_ linuxaio_submits [submitted], EPOLL_CTL_ADD);
            iocb->aio_reqprio = -1; /* mark iocb as epoll */

            res = 1; /* skip this iocb */
          }
#endif
        else if (errno == EBADF)
          {
            fd_kill (EV_A_ linuxaio_submits [submitted]->aio_fildes);

            res = 1; /* skip this iocb */
          }
        else
          ev_syserr ("(libev) linuxaio io_submit");

      submitted += res;
    }

  linuxaio_submitcnt = 0;

  /* second phase: fetch and parse events */

  linuxaio_get_events (EV_A_ timeout);
}

inline_size
int
linuxaio_init (EV_P_ int flags)
{
  /* would be great to have a nice test for IOCB_CMD_POLL instead */
  /* also: test some semi-common fd types, such as files and ttys in recommended_backends */
#if EPOLL_FALLBACK
  /* 4.19 made epoll work */
  if (ev_linux_version () < 0x041300)
    return 0;
#else
  /* 4.18 introduced IOCB_CMD_POLL */
  if (ev_linux_version () < 0x041200)
    return 0;
#endif

  linuxaio_ctx = 0;
  if (evsys_io_setup (EV_LINUXAIO_DEPTH, &linuxaio_ctx) < 0)
    return 0;

#if EPOLL_FALLBACK
  backend_fd = ev_epoll_create ();
  if (backend_fd < 0)
    {
      evsys_io_destroy (linuxaio_ctx);
      return 0;
    }

  ev_io_init  (EV_A_ &linuxaio_epoll_w, linuxaio_epoll_cb, backend_fd, EV_READ);
  ev_set_priority (&linuxaio_epoll_w, EV_MAXPRI);
  ev_io_start (EV_A_ &linuxaio_epoll_w);
  ev_unref (EV_A); /* watcher should not keep loop alive */
#endif

  backend_modify  = linuxaio_modify;
  backend_poll    = linuxaio_poll;

  linuxaio_iocbpmax = 0;
  linuxaio_iocbps = 0;

  linuxaio_submits = 0;
  linuxaio_submitmax = 0;
  linuxaio_submitcnt = 0;

  return EVBACKEND_LINUXAIO;
}

inline_size
void
linuxaio_destroy (EV_P)
{
#if EPOLL_FALLBACK
  close (backend_fd);
#endif
  linuxaio_free_iocbp (EV_A);
  evsys_io_destroy (linuxaio_ctx);
}

inline_size
void
linuxaio_fork (EV_P)
{
  /* this frees all iocbs, which is very heavy-handed */
  linuxaio_destroy (EV_A);
  linuxaio_submitcnt = 0; /* all pointers were invalidated */

  linuxaio_ctx = 0;
  while (evsys_io_setup (EV_LINUXAIO_DEPTH, &linuxaio_ctx) < 0)
    ev_syserr ("(libev) linuxaio io_setup");

#if EPOLL_FALLBACK
  while ((backend_fd = ev_epoll_create ()) < 0)
   ev_syserr ("(libev) linuxaio epoll_create");

  ev_io_stop  (EV_A_ &linuxaio_epoll_w);
  ev_io_init  (EV_A_ &linuxaio_epoll_w, linuxaio_epoll_cb, backend_fd, EV_READ);
  ev_io_start (EV_A_ &linuxaio_epoll_w);
#endif

  fd_rearm_all (EV_A);
}

