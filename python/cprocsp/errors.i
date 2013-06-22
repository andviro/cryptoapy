/* vim: ft=swig
*/
%typemap(throws) CSPException %{
  PyErr_SetString(PyExc_SystemError, $1.msg);
  SWIG_fail;
%}
