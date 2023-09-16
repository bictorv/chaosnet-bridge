/* Copyright (C) 2022, 2023 Lars Brinkhoff <lars@nocrew.org>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tape-image.h"

static int marks;

int
read_tape (const char *file)
{
  int fd = open (file, O_RDONLY);
  marks = 0;
  return fd;
}

int
write_tape (const char *file)
{
  int fd = open (file, O_WRONLY | O_CREAT, 0600);
  marks = 0;
  return fd;
}

int
rw_tape (const char *file)
{
  int fd = open (file, O_RDWR | O_CREAT, 0600);
  marks = 0;
  return fd;
}

static size_t
read_reclen (int fd)
{
  unsigned char size[4];
  size_t n;

  n = read (fd, size, 4);
  if (n == -1) {
    fprintf (stderr, "Read error: %s\n", strerror (errno));
    return RECORD_ERR | errno;
  } else if (n == 0) {
    return RECORD_EOM;
  } else if (n < 4) {
    return RECORD_ERR;
  }

  n = size[0];
  n |= (size_t)size[1] << 8;
  n |= (size_t)size[2] << 16;
  n |= (size_t)size[3] << 24;
  return n;
}

size_t
read_record (int fd, void *buffer, size_t n)
{
  char zero;
  size_t n1, n2;

  n1 = read_reclen(fd);
  if (n1 & RECORD_ERR)
    return n1;
  if (n1 == RECORD_MARK)
    return n1;

  if (n1 > n)
    n1 = n;
  n2 = read (fd, buffer, n1);
  if (n2 == -1) {
    fprintf (stderr, "Read error: %s\n", strerror (errno));
    return RECORD_ERR | errno;
  }

  if (n1 & 1) {
    n2 = read (fd, &zero, 1);
    if (n2 == -1) {
      fprintf (stderr, "Read error: %s\n", strerror (errno));
      return RECORD_ERR | errno;
    }
  }

  n2 = read_reclen(fd);
  if (n2 & RECORD_ERR)
    return n2;
  if (n1 != n2)
    return RECORD_ERR;
}

static void
write_reclen (int fd, size_t n)
{
  unsigned char size[4];

  size[0] = n & 0377;
  size[1] = (n >> 8) & 0377;
  size[2] = (n >> 16) & 0377;
  size[3] = (n >> 24) & 0377;

  n = write (fd, size, 4);
  if (n == -1)
    fprintf (stderr, "Write error: %s\n", strerror (errno));
}

void
write_mark (int fd)
{
  marks++;
  write_reclen (fd, RECORD_MARK);
}

void
write_record (int fd, const void *buffer, size_t n)
{
  char zero = 0;
  int m;
  n &= RECORD_LMASK;
  if (n == 0)
    {
      fprintf (stderr, "Can't write empty record.\n");
      return;
    }
  marks = 0;
  write_reclen (fd, n);
  m = write (fd, buffer, n);
  if (m == -1)
    fprintf (stderr, "Write error: %s\n", strerror (errno));
  if (n & 1) {
    m = write (fd, &zero, 1);
    if (m == -1)
      fprintf (stderr, "Write error: %s\n", strerror (errno));
  }
  write_reclen (fd, n);
}

void
write_eot (int fd)
{
  int i;
  for (i = marks; i < 2; i++)
    write_mark (fd);
}

void
write_eom (int fd)
{
  write_reclen (fd, RECORD_EOM);
}

void
write_error (int fd, unsigned error)
{
  error &= RECORD_EMASK;
  write_reclen (fd, error | RECORD_ERR);
}
