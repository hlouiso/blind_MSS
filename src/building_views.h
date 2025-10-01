#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void building_views(a *a, unsigned char digest[32], unsigned char *shares[3], unsigned char *randomness[3],
                    View *views[3]);

#endif // BUILDING_H