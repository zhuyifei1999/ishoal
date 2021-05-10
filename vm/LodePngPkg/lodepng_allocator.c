#include <Library/MemoryAllocationLib.h>

#include "lodepng_allocator.h"

void *lodepng_malloc(
  IN size_t size
  )
{
  void *ptr = AllocatePool(size + sizeof(size_t));
  *(size_t *)ptr = size;
  return ptr + sizeof(size_t);
}

void lodepng_free(
  IN void *ptr
  )
{
  if (!ptr)
    return;
  return FreePool(ptr - sizeof(size_t));
}

void *lodepng_realloc(
  IN void *ptr,
  IN size_t new_size
  )
{
  if (!ptr) {
    return lodepng_malloc(new_size);
  } else if (!new_size) {
    lodepng_free(ptr);
    return NULL;
  }

  void *old_head = ptr - sizeof(size_t);
  size_t old_size = *(size_t *)old_head;
  ptr = ReallocatePool(old_size, new_size, old_head);
  if (!ptr)
    return NULL;

  *(size_t *)ptr = new_size;
  return ptr + sizeof(size_t);
}
