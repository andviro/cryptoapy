/* vim: ft=swig
*/
#define WINBASEAPI


WINBASEAPI DWORD WINAPI GetLastError(void);

WINBASEAPI void WINAPI SetLastError(DWORD dwErr);   //Sets error code
