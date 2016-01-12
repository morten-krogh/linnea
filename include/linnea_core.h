#ifndef LINNEA_CORE_H
#define LINNEA_CORE_H

#include <stddef.h>
#include <stdlib.h>


struct core_state {
	void *app_state;

};


void linnea_core_init(void);

#endif
