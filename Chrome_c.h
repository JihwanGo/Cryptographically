#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <time.h>
#include <math.h>

void DirectorySearch(char *PATH);
int ExeFileExcep(char *PATH);
int HwpFileDetec(char *PATH, struct _finddatai64_t find_file);
int MsoffxFileDetec(char *PATH, struct _finddatai64_t find_file);
int	EncrypFileDetec(char *PATH, struct _finddatai64_t find_file);
int CompFileDetec(char *PATH, struct _finddatai64_t find_file);
char* TimeToString(struct tm *t);

extern int Crypto_count;
extern int Compres_count;

