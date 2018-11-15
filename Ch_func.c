#include "Chrome_c.h"

void DirectorySearch(char *PATH)
{
	intptr_t hFile;
	struct _finddatai64_t find_file;
	char search_path[MAX_PATH];
	char searched_path[MAX_PATH];
	char search_option[] = "\\*.*";

	strcpy_s(search_path, sizeof(search_path), PATH);
	strncat_s(search_path, sizeof(search_path), search_option, strlen(search_option));

	printf("%s\n\n", PATH);								// 탐색 디렉토리 정보 출력 !

	hFile = _findfirsti64(search_path, &find_file);

	if (hFile == -1)
	{
		switch (errno)
		{
		case ENOENT:
			fputs("File does not exist.\n", stderr); break;
		case EINVAL:
			fputs("Invalid path name.\n", stderr); break;
		case ENOMEM:
			fputs("Not enough memory or file name too long.\n", stderr); break;
		default:
			fputs("Unknown error.\n", stderr); break;
		}
	}
	else
	{
		do
		{
			if (strcmp(find_file.name, ".") && strcmp(find_file.name, ".."))
			{
				sprintf_s(searched_path, sizeof(searched_path), "%s\\%s", PATH, find_file.name);

				if (ExeFileExcep(searched_path))				// 실행파일 파일 예외처리
				{
					if (_access(searched_path, 4)) continue;	// 파일및 폴더에 권한이 없을 경우 예외처리

					if (find_file.attrib & _A_SUBDIR)
					{
						DirectorySearch(searched_path);			// 디렉토리일경우 새로운 디렉토리로 이름 변경 후 재귀함수
						printf("\n");
						continue;
					}

					if (find_file.size == 0) continue;							// 파일 사이즈가 0인 경우 예외처리	

					if (HwpFileDetec(searched_path, find_file)) continue;		// hwp파일 암호화 탐지

					if (MsoffxFileDetec(searched_path, find_file)) continue;	// DOCX, PPTX, XLSX 파일 암호화 탐지

					if (EncrypFileDetec(searched_path, find_file)) continue;	// 엔트로피 암호화파일 탐지

					CompFileDetec(searched_path, find_file);					// 압축파일 탐지
				}
			}

		} while (_findnexti64(hFile, &find_file) == 0);

		_findclose(hFile);		// _findfirsti64(), _findnexti64()에 사용된 메모리를 반환
	}
}

int ExeFileExcep(char *PATH)
{
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	char rsig[16];
	FILE * rFile;

	_splitpath_s(PATH, drive, 3, dir, 256, fname, 256, ext, 256);

	if (ext[0] == '.' && ext[1] == 'e' && ext[2] == 'x' && ext[3] == 'e')
	{
		rFile = _fsopen(PATH, "r", _SH_DENYWR);

		if (rFile == NULL)
		{
			printf(".exe File open error. \n");
			exit(0);
		}

		fread(rsig, 2, 1, rFile);

		if (rsig[0] == 'M' && rsig[1] == 'Z') // 실행파일 signature MZ 판단!
		{
			fclose(rFile);
			return 0;
		}
		fclose(rFile);
	}
	return 1;
}

int HwpFileDetec(char *PATH, struct _finddatai64_t find_file)
{
	unsigned char fc = 0;
	char rsig[16] = { 0 };
	int offset = 0;
	int result = 0;
	struct tm t;
	FILE * rFile;
	rFile = _fsopen(PATH, "rb", _SH_DENYWR);

	if (rFile == NULL)
	{
		printf("hwp_ File read error!\n");
		exit(0);
	}

	while (1)
	{
		fread(rsig, 16, 1, rFile);
		rsig[12] = '\0';

		if (feof(rFile) != 0) break;

		if (strcmp(rsig, "HWP Document") == 0)
		{
			fread(rsig, 16, 1, rFile);
			if (rsig[1] != '\0' && rsig[2] != '\0')
			{
				fseek(rFile, -16, SEEK_CUR);
				continue;
			}

			fseek(rFile, 4, SEEK_CUR);
			fc = fgetc(rFile);
			if ((fc & 2) == 2) result = 1;
			else
			{
				fseek(rFile, -5, SEEK_CUR);
				continue;
			}
		}
	}

	if (result == 1)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		printf("┌[ 암호화 파일 - (HWP 판단) ]\n");
		printf("│ 파일 경로 : %s\n", PATH);
		printf("│ 수정 날짜 : %s\n", TimeToString(&t));
		printf("└ 파일 크기 : %.2lf KB\n\n", (double)find_file.size / (double)1024);
	}

	fclose(rFile);
	return result;
}

int MsoffxFileDetec(char *PATH, struct _finddatai64_t find_file)
{
	char rsig[16] = { 0 };
	int offset = 0;
	int result = 0;
	struct tm t;
	FILE * fp;
	fp = _fsopen(PATH, "rb", _SH_DENYWR);

	if (fp == NULL)
	{
		printf("MS_ File read error!\n");
		exit(0);
	}

	fread(rsig, 8, 1, fp);

	if (rsig[0] = '\xD0' && rsig[1] == '\xCF' && rsig[2] == '\x11')
	{
		fseek(fp, 2048, SEEK_SET);
		fread(rsig, 16, 1, fp);

		if (rsig[0] == '<' && rsig[4] == 'M' && rsig[6] == 'i' && rsig[8] == 'c')
			result = 1;

		if (result != 1)
		{
			fseek(fp, 2304, SEEK_SET);
			fread(rsig, 16, 1, fp);

			if (rsig[0] == '<' && rsig[4] == 'M' && rsig[6] == 'i' && rsig[8] == 'c')
				result = 1;
		}
	}

	if (result == 1)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		printf("┌[ 암호화 파일 - (DOCX, PPTX, XLSX 판단) ]\n");
		printf("│ 파일 경로 : %s\n", PATH);
		printf("│ 수정 날짜 : %s\n", TimeToString(&t));
		printf("└ 파일 크기 : %.2lf KB\n\n", (double)find_file.size / (double)1024);
	}

	fclose(fp);
	return result;
}

int	EncrypFileDetec(char *PATH, struct _finddatai64_t find_file)
{
	char pnum[8] = { 0 };
	char psig[8] = { 0 };
	char rsig[16] = { 0 };
	struct tm t;
	FILE * rFile;
	FILE * rPatton;
	long byte_count[256] = { 0 };
	unsigned char buffer[1024] = { 0 };
	int i, n, length, offset, psiglen, sigcf, result;
	long long kbrn;
	float count, entropy, rPentropy;

	i = n = length = offset = psiglen = sigcf = result = 0;
	count = entropy = rPentropy = 0.0;

	rFile = _fsopen(PATH, "rb", _SH_DENYWR);
	rPatton = _fsopen("patton.txt", "r", _SH_DENYWR);

	memset(byte_count, 0, sizeof(long) * 256);

	if (rFile == NULL)
	{
		printf("Encryption files read error!\n");
		exit(0);
	}
	if (rPatton == NULL)
	{
		printf("Patton files read error!\n");
		exit(0);
	}

	// Read the whole file in parts of 1024
	for (kbrn = (find_file.size / 1024) + 1; kbrn != 0; kbrn--)
	{
		fread(buffer, 1024, 1, rFile);

		if (kbrn == 1)
			n = (find_file.size % 1024);
		else
			n = 1024;

		// Add the buffer to the byte_count
		for (i = 0; i < n; i++)
		{
			byte_count[(int)buffer[i]]++;
			length++;
		}
	}

	for (i = 0; i < 256; i++)			// 엔트로피 계산
	{
		if (byte_count[i] != 0)
		{
			count = (float)byte_count[i] / (float)length;
			entropy += -count * log2f(count);
		}
	}

	while (1)
	{
		fscanf_s(rPatton, "%s %s %d %f", pnum, sizeof(pnum), psig, sizeof(psig), &offset, &rPentropy);

		if (feof(rPatton) != 0) break;
		if (pnum[0] != 'E') continue;					// 패턴 식별번호 확인.

		fseek(rFile, offset, SEEK_SET);
		fread(rsig, 8, 1, rFile);

		psiglen = strlen(psig) - 1;

		for (i = 0, sigcf = 0; i < psiglen; i++)
		{
			if (psig[i] == rsig[i]) sigcf++;
		}

		if (rsig[0] == 'P' && rsig[1] == 'K')
			if (rsig[6] != 0) continue;

		if (sigcf == psiglen) break;
		else if (strcmp(rsig, "EALL") == 0) break;
	}

	if (entropy >= rPentropy) result = 1;

	if (result == 1)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		printf("┌[ 암호화 파일 - (엔트로피 판단) ]\n");
		printf("│ 파일 경로 : %s\n", PATH);
		printf("│ 수정 날짜 : %s\n", TimeToString(&t));
		printf("└ 파일 크기 : %.2lf KB\n\n", (double)find_file.size / (double)1024);
	}

	fclose(rFile);
	fclose(rPatton);

	return result;
}

int CompFileDetec(char *PATH, struct _finddatai64_t find_file)
{
	int i = 0;
	int offset;
	int psiglen;
	int sigcf = 0;
	int result = 0;
	float dummy = 0.0;
	struct tm t;
	char pnum[8] = { 0 };
	char psig[8] = { 0 };
	char rsig[16] = { 0 };
	FILE * rFile;
	FILE * rPatton;

	rFile = _fsopen(PATH, "rb", _SH_DENYWR);
	rPatton = _fsopen("patton.txt", "r", _SH_DENYWR);

	if (rFile == NULL)
	{
		printf("Compressed files read error!\n");
		exit(0);
	}
	if (rPatton == NULL)
	{
		printf("Compressed Patton files read error!\n");
		exit(0);
	}

	while (1)
	{
		fscanf_s(rPatton, "%s %s %d %f", pnum, sizeof(pnum), psig, sizeof(psig), &offset, &dummy);

		if (feof(rPatton) != 0) break;
		if (pnum[0] != 'C') continue;					// 압축파일	패턴 식별번호 확인.

		fseek(rFile, offset, SEEK_SET);
		fread(rsig, 8, 1, rFile);

		psiglen = strlen(psig) - 1;

		for (i = 0, sigcf = 0; i < psiglen; i++)
		{
			if (psig[i] == rsig[i]) sigcf++;
		}

		if (rsig[0] == 'P' && rsig[1] == 'K')		// MS Office file 압축파일 예외처리
			if (rsig[6] != 0) continue;

		if (sigcf == psiglen) result = 1;
	}

	if (result == 1)
	{
		Compres_count++;
		localtime_s(&t, &find_file.time_write);

		printf("┌[ 압축 파일 ]\n");
		printf("│ 파일 경로 : %s\n", PATH);
		printf("│ 수정 날짜 : %s\n", TimeToString(&t));
		printf("└ 파일 크기 : %.2lf KB\n\n", (double)find_file.size / (double)1024);
	}

	fclose(rFile);
	fclose(rPatton);

	return result;
}

char* TimeToString(struct tm *t)
{
	static char s[20];

	sprintf_s(s, sizeof(s), "%04d-%02d-%02d %02d:%02d:%02d",
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec
		);

	return s;
}