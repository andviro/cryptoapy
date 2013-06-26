/* vim: ft=swig
*/
%newobject Cert::name;
%newobject Cert::issuer;
%newobject Cert::thumbprint;
%newobject Cert::sign_algorithm;
%newobject Cert::duplicate;
%newobject Cert::extract;
%newobject Cert::self_sign;
%newobject CertStore::__iter__;
%newobject CertStore::add_cert;
%newobject CertStore::find_by_thumb;
%newobject CertStore::find_by_name;
%newobject CertStore::get_cert_by_info;
%newobject CertIter::next;
%newobject CertFind::next;

%feature("ref") CertStore "$this->ref();"
%feature("unref") CertStore "$this->unref();"
%feature("python:slot", "tp_iter", functype="getiterfunc") CertStore::__iter__;
%feature("python:slot", "tp_iter", functype="getiterfunc") CertIter::__iter__;
%feature("python:slot", "tp_iternext", functype="iternextfunc") CertIter::next;

%include "cert.hpp"
