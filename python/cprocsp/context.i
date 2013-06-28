/* vim: ft=swig
*/
%feature("ref") Crypt "if ($this) $this->ref();"
%feature("unref") Crypt "if ($this) $this->unref();"
%newobject Crypt::get_key;
%newobject Crypt::import_key;
%newobject Crypt::create_key;
%newobject Crypt::name;
%newobject Crypt::prov_name;
%newobject Crypt::uniq_name;
%newobject ::Context;

%include "context.hpp"
