#include <iostream>
#include <cstdlib>
#include <cstring>	
#include <fstream>	
#include <windows.h>
#include <io.h>
#include <cerrno>
#include <ctime>
#include <cmath>
using namespace std;

class FileDetec
{
private:
	char rsig[16];
	char psig[8];
	char pnum[8];
	int offset;
	bool result;
	ifstream rFile;
	ifstream rPatton;
	tm t;

public:
	bool ExeFileExcep(char *PATH);
	bool HwpFileDetec(char *PATH, _finddatai64_t find_file);
	bool MsoffxFileDetec(char *PATH, _finddatai64_t find_file);
	bool EncrypFileDetec(char *PATH, _finddatai64_t find_file);
	bool CompFileDetec(char *PATH, _finddatai64_t find_file);
	char* TimeToString(tm *t);
};

class EncrypDetecProgram
{
private:
	_finddatai64_t find_file;
	FileDetec filedata;

public:
	EncrypDetecProgram(char *PATH)
	{
		DirectorySearch(PATH);
	}
	void DirectorySearch(char *PATH);
};

extern int Crypto_count;
extern int Compres_count;
