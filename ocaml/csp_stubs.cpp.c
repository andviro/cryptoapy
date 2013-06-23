// vim: ft=cpp
#include "common.hpp"
#include "context.hpp"
#include "cert.hpp"
#include "except.hpp"
#include "key.hpp"
#include "msg.hpp"
#include "rcobj.hpp"
#include "sign.hpp"

extern "C" {
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/mlvalues.h>
#include <caml/custom.h>
}

void finalize_Crypt( value v )
{
    Crypt* my_obj;
    my_obj = (Crypt *) Data_custom_val(v);
    if (my_obj) {
        my_obj->unref();
    }
}

static struct custom_operations Crypt_custom_ops = {
identifier:
    "Crypt handling"
    ,
finalize:
    finalize_Crypt,
compare:
    custom_compare_default,
hash:
    custom_hash_default,
serialize:
    custom_serialize_default,
deserialize:
    custom_deserialize_default
};


#define Crypt_val(v) (*((Crypt **) Data_custom_val(v)))

static value alloc_Crypt(Crypt * ctx)
{
    value v = alloc_custom(&Crypt_custom_ops, sizeof(Crypt *), 0, 1);
    Crypt_val(v) = ctx;
    return v;
}

extern "C" CAMLprim value new_Context (value cont, value type, value flags, value name)
{
    Crypt *res;
    CAMLparam4 (cont, type, flags, name);
    try {
        res = Context(String_val(cont), Int_val(type), Int_val(flags), String_val(name));
    } catch (CSPException(e)) {
        caml_failwith(e.msg);
    }
    CAMLreturn (alloc_Crypt(res));
}

