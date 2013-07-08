/* vim: ft=swig
*/
%feature("ref") Crypt "$this->ref();"
%feature("unref") Crypt "$this->unref();"
%newobject Crypt::get_key;
%newobject Crypt::import_key;
%newobject Crypt::create_key;
%newobject Crypt::name;
%newobject Crypt::prov_name;
%newobject Crypt::uniq_name;

%include "context.hpp"
