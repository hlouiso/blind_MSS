#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"

#include <stdbool.h>

void building_views(a *a, unsigned char digest[32], unsigned char *shares[3], unsigned char *randomness[3],
                    View *views[3]);

void verify(unsigned char digest[32], bool *error, a *a, int e, z *z);

#endif // BUILDING_H