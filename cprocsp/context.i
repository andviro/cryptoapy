/* vim: ft=swig
*/

%rename(CryptAcquireContext) CryptAcquireContextA;
%apply HCRYPTPROV *OUTPUT { HCRYPTPROV *phProv };

WINADVAPI
BOOL
WINAPI
CryptAcquireContextA(
    HCRYPTPROV *phProv,
    LPCSTR pszContainer,
    LPCSTR pszProvider,
    DWORD dwProvType,
    DWORD dwFlags);

WINADVAPI
BOOL
WINAPI
CryptReleaseContext(
    HCRYPTPROV hProv,
    DWORD dwFlags
    );

