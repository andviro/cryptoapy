/* vim: ft=swig
*/

%rename(CryptAcquireContext) CryptAcquireContextA;

WINADVAPI
BOOL
WINAPI
CryptAcquireContextA(
    HCRYPTPROV *OUTPUT,
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

