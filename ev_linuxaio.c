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

#include <sys/time.h> /* actually linux/time.h, but we must assume they are compatible */
#include <poll.h>
#include <linux/aio_abi.h>

/* we try to fill 4kB pages exactly.
 * the ring buffer header is 32 bytes, every io event is 32 bytes.
 * the kernel takes the io event number, doubles it, adds 2, adds the ring buffer.
 * therefore the calculation below will use "exactly" 4kB for the ring buffer
 */
#define EV_LINUXAIO_DEPTH (128 / 2 - 2 - 1) /* max. number of io events per batch */

/*****************************************************************************/
/* syscall wrapdadoop */

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
ev_io_setup (unsigned nr_events, aio_context_t *ctx_idp)
{
  return syscall (SYS_io_setup, nr_events, ctx_idp);
}

inline_size
int
ev_io_destroy (aio_context_t ctx_id)
{
  return syscall (SYS_io_destroy, ctx_id);
}

inline_size
int
ev_io_submit (aio_context_t ctx_id, long nr, struct iocb *cbp[])
{
  return syscall (SYS_io_submit, ctx_id, nr, cbp);
}

inline_size
int
ev_io_cancel (aio_context_t ctx_id, struct iocb *cbp, struct io_event *result)
{
  return syscall (SYS_io_cancel, ctx_id, cbp, result);
}

inline_size
int
ev_io_getevents (aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout)
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
linuxaio_array_needsize_iocbp (ANIOCBP *base, int count)
{
  /* TODO: quite the overhead to allocate every iocb separately, maybe use our own alocator? */
  while (count--)
    {
      *base = (ANIOCBP)ev_malloc (sizeof (**base));
      /* TODO: full zero initialize required? */
      memset (*base, 0, sizeof (**base));
      /* would be nice to initialize fd/data as well, but array_needsize API doesn't support that */
      (*base)->io.aio_lio_opcode = IOCB_CMD_POLL;
      ++base;
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
  struct aniocb *iocb = linuxaio_iocbps [fd];

  if (iocb->io.aio_buf)
    ev_io_cancel (linuxaio_ctx, &iocb->io, (struct io_event *)0); /* always returns an error relevant kernels */

  if (nev)
    {
      iocb->io.aio_data       = fd;
      iocb->io.aio_fildes     = fd;
      iocb->io.aio_buf        =
          (nev & EV_READ ? POLLIN : 0)
          | (nev & EV_WRITE ? POLLOUT : 0);

      /* queue iocb up for io_submit */
      /* this assumes we only ever get one call per fd per loop iteration */
      ++linuxaio_submitcnt;
      array_needsize (struct iocb *, linuxaio_submits, linuxaio_submitmax, linuxaio_submitcnt, array_needsize_noinit);
      linuxaio_submits [linuxaio_submitcnt - 1] = &iocb->io;
    }
}

static void
linuxaio_parse_events (EV_P_ struct io_event *ev, int nr)
{
  while (nr)
    {
      int fd  = ev->data;
      int res = ev->res;

      assert (("libev: iocb fd must be in-bounds", fd >= 0 && fd < anfdmax));

      /* linux aio is oneshot: rearm fd */
      linuxaio_iocbps [fd]->io.aio_buf = 0;
      anfds [fd].events = 0;
      fd_change (EV_A_ fd, 0);

      /* feed events, we do not expect or handle POLLNVAL */
      if (ecb_expect_false (res & POLLNVAL))
        fd_kill (EV_A_ fd);
      else
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

  unsigned head = ring->head;
  unsigned tail = *(volatile unsigned *)&ring->tail;

  if (head == tail)
    return 0;

  /* bail out if the ring buffer doesn't match the expected layout */
  if (ecb_expect_false (ring->magic != AIO_RING_MAGIC)
                        || ring->incompat_features != AIO_RING_INCOMPAT_FEATURES
                        || ring->header_length != sizeof (struct aio_ring)) /* TODO: or use it to find io_event[0]? */
    return 0;

  ECB_MEMORY_FENCE_ACQUIRE;

  /* parse all available events, but only once, to avoid starvation */
  if (tail > head) /* normal case around */
    linuxaio_parse_events (EV_A_ ring->io_events + head, tail - head);
  else /* wrapped around */
    {
      linuxaio_parse_events (EV_A_ ring->io_events + head, ring->nr - head);
      linuxaio_parse_events (EV_A_ ring->io_events, tail);
    }

  ring->head = tail;

  return 1;
}

/* read at least one event from kernel, or timeout */
inline_size
void
linuxaio_get_events (EV_P_ ev_tstamp timeout)
{
  struct timespec ts;
  struct io_event ioev;
  int res;

  if (linuxaio_get_events_from_ring (EV_A))
    return;

  /* no events, so wait for at least one, then poll ring buffer again */
  /* this degrades to one event per loop iteration */
  /* if the ring buffer changes layout, but so be it */

  ts.tv_sec  = (long)timeout;
  ts.tv_nsec = (long)((timeout - ts.tv_sec) * 1e9);

  res = ev_io_getevents (linuxaio_ctx, 1, 1, &ioev, &ts);

  if (res < 0)
    ev_syserr ("(libev) linuxaio io_getevents");
  else if (res)
    {
      /* at least one event received, handle it and any remaining ones in the ring buffer */
      linuxaio_parse_events (EV_A_ &ioev, 1);
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
      int res = ev_io_submit (linuxaio_ctx, linuxaio_submitcnt - submitted, linuxaio_submits + submitted);

      if (ecb_expect_false (res < 0))
        if (errno == EAGAIN)
          {
            /* This happens when the ring buffer is full, at least. I assume this means
             * that the event was queued synchronously during io_submit, and thus
             * the buffer overflowd.
             * In this case, we just try next loop iteration.
             * This should not result in a few fds taking priority, as the interface
             * is one-shot, and we submit iocb's in a round-robin fashion.
             */
            memmove (linuxaio_submits, linuxaio_submits + submitted, (linuxaio_submitcnt - submitted) * sizeof (*linuxaio_submits));
            linuxaio_submitcnt -= submitted;
            timeout = 0;
            break;
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
  if (ev_linux_version () < 0x041200) /* 4.18 introduced IOCB_CMD_POLL */
    return 0;

  linuxaio_ctx = 0;
  if (ev_io_setup (EV_LINUXAIO_DEPTH, &linuxaio_ctx) < 0)
    return 0;

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
  linuxaio_free_iocbp (EV_A);
  ev_io_destroy (linuxaio_ctx);
}

inline_size
void
linuxaio_fork (EV_P)
{
  /* this frees all iocbs, which is very heavy-handed */
  linuxaio_destroy (EV_A);
  linuxaio_submitcnt = 0; /* all pointers were invalidated */

  linuxaio_ctx = 0;
  while (ev_io_setup (EV_LINUXAIO_DEPTH, &linuxaio_ctx) < 0)
    ev_syserr ("(libev) linuxaio io_setup");

  fd_rearm_all (EV_A);
}

