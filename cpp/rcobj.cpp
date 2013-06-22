#include "common.hpp"
#include "rcobj.hpp"

int RCObj::ref()
{
    refcount ++;
    LOG("ref %i\n", refcount);
    return refcount;
}

int RCObj::unref()
{
    refcount --;
    if (refcount <= 0) {
        LOG("delete \n");
        delete this;
        return 0;
    }
    LOG("unref %i\n", refcount);
    return refcount;
}
