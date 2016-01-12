#include <stdlib.h>

void *linnea_util_malloc(size_t size)
{
	void *memory = malloc(size);
	if (memory == NULL) abort();
	return memory;
}
