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

#define RECORD_MARK   0x00000000  /* Tape mark. */
#define RECORD_LMASK  0x7FFFFFFF  /* Record length mask. */
#define RECORD_ERR    0x80000000  /* Error. */
#define RECORD_EMASK  0x00FFFFFF  /* Error mask. */
#define RECORD_EOM    0xFFFFFFFF  /* End of medium. */

extern int read_tape (const char *file);
extern int write_tape (const char *file);
extern int rw_tape (const char *file);
extern size_t read_record (int fd, void *buffer, size_t n);
extern void write_record (int fd, const void *buffer, size_t n);
extern void write_mark (int fd);
extern void write_eot (int fd);
extern void write_eom (int fd);
extern void write_error (int fd, unsigned error);
