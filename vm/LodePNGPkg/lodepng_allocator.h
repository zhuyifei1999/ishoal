#ifndef _LODEPNG_ALLOCATOR_H
#define _LODEPNG_ALLOCATOR_H

#include <Uefi.h>
#include <string.h> /* for size_t */

void *lodepng_malloc(
  IN size_t size
  );

void lodepng_free(
  IN void *ptr
  );

void *lodepng_realloc(
  IN void *ptr,
  IN size_t new_size
  );

#endif
