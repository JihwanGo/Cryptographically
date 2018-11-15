#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <time.h>

void DirectorySearch(char *PATH);
int EXE_FileException(char *PATH);
int Compressed_File(char *PATH, _int64 time_create, _int64 time_access, _int64 time_write, _int64 size);
int hwp(char *PATH, _int64 time_create, _int64 time_access, _int64 time_write, _int64 size);
char* timeToString(struct tm *t);

int DT;

int main(int argc, char *argv[])
{
	if (argc == 1)
	{
		printf("Error! \n디렉토리 정보를 입력 해주세요.\n");
		exit(0);
	}
	else if (argc >= 3)
	{
		printf("Error! \n디렉토리 정보를 한개만 입력 해주세요.\n");
		exit(0);
	}

	printf("\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	printf("  ■■■   		                                    \n");
	printf(" ■    ■  ■                                          \n");
	printf("■         ■       ■         ■■■    ■■  ■■    ■■■    \n");
	printf("■         ■■■   ■ ■■   ■    ■  ■  ■■  ■  ■     ■   \n");
	printf("■         ■   ■  ■■  ■  ■    ■  ■   ■   ■  ■■■■   \n");
	printf(" ■    ■  ■   ■  ■        ■    ■  ■   ■   ■  ■         \n");
	printf("  ■■■   ■   ■  ■         ■■■   ■        ■   ■■■■   \n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	printf("                         암호화 파일 판단 프로그램 [Version 0.1] \n  \n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	printf("                   팀원 : 문성현, 황호성, 고동현, 정광수, 황지환\n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf("                  Copyright (c) 2016 Chrome. All rights reserved \n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	puts("\n\n\n");
	system("pause");
	system("cls");


	DirectorySearch(argv[1]);

	return 0;
}

void DirectorySearch(char *PATH)
{
	intptr_t hFile;
	_finddatai64_t find_file;
	char search_path[MAX_PATH];
	char searched_path[MAX_PATH];
	char search_option[] = "\\*.*";
	int cr = 0;

	strcpy_s(search_path, PATH);
	strncat_s(search_path, sizeof(search_path), search_option, strlen(search_option));

	printf("%s\n\n", PATH);

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
			fputs("Not enough memory or file name too long.\n", stderr); exit(1); break;
		default:
			fputs("Unknown error.\n", stderr); exit(1); break;
		}
	}
	else
	{
		do
		{
			if (strcmp(find_file.name, ".") && strcmp(find_file.name, ".."))
			{
				sprintf_s(searched_path, sizeof(searched_path), "%s\\%s", PATH, find_file.name);

				if (EXE_FileException(searched_path))	// 실행파일 파일 예외처리
				{
					if (find_file.attrib & _A_SUBDIR)
					{
						DirectorySearch(searched_path); // 디렉토리일경우 새로운 디렉토리로 이름 변경 후 재귀함수
						printf("\n");
						continue;
					}

					if (!find_file.size) continue;		// 파일 사이즈 0인 경우 예외처리	

					if (access(searched_path, 4)) continue;

					printf("%s\n", searched_path);
					
					Compressed_File(searched_path, find_file.time_create,
						find_file.time_access,
						find_file.time_write, find_file.size);	// 압축파일 탐지
						
				}

			}

		} while (_findnexti64(hFile, &find_file) == 0);

		_findclose(hFile);		// _findfirsti64(), _findnexti64()에 사용된 메모리를 반환.
	}
}

int EXE_FileException(char *PATH)
{
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	char signature[10];
	FILE * file_read;

	_splitpath_s(PATH, drive, 3, dir, 256, fname, 256, ext, 256);

	if (ext[0] == '.' && ext[1] == 'e' && ext[2] == 'x' && ext[3] == 'e')
	{
		file_read = _fsopen(PATH, "r", _SH_DENYWR);

		if (file_read == NULL)
		{
			fputs(".exe File open error. \n", stderr);
			exit(0);
		}

		fread(signature, 2, 1, file_read);

		if (signature[0] == 'M' && signature[1] == 'Z') // 실행파일 signature MZ 판단!
		{
			fclose(file_read);
			return 0;
		}
		fclose(file_read);
	}
	return 1;
}

int Compressed_File(char *PATH, _int64 time_create, _int64 time_access, _int64 time_write, _int64 size)
{
	int i = 0;
	int offset;
	int psiglen;
	int sigcf = 0;
	int result = 0;
	struct tm *t;
	char pnum[8] = { 0 };
	char psig[8] = { 0 };
	char rsig[8] = { 0 };
	FILE * rFile;
	FILE * rPatton;

	rFile = _fsopen(PATH, "r", _SH_DENYWR);
	rPatton = _fsopen("D:\\patton_2.txt", "r", _SH_DENYWR);

	while (1)
	{
		fscanf_s(rPatton, "%s %s %d", pnum, sizeof(pnum), psig, sizeof(pnum), &offset);

		if (feof(rPatton) != NULL) break;
		if (pnum[0] != 'C') continue;					// 압축파일	패턴 식별번호 확인.

		fseek(rFile, offset, SEEK_SET);
		fread(rsig, 8, 1, rFile);

		psiglen = strlen(psig) - 1;

		for (i = 0, sigcf = 0; i < psiglen; i++)
		{
			if (psig[i] == rsig[i]) sigcf++;
		}

		if (sigcf == psiglen) result = 1;
		if (rsig[0] == 'P' && rsig[1] == 'K')			// MS Office file 압축파일 예외처리
		{
			if (rsig[6] == '\x06' && rsig[7] == '\x00') result = 0;
		}
	}

	if (result == 1)
	{
		t = localtime(&time_write);

		printf("┌ 압축파일\n");
		printf("│ 파일 경로 : %s\n", PATH);
		printf("│ 수정 날짜 : %s\n", timeToString(t));
		printf("└ 파일 크기 : %.2lf KB\n\n", (double)size / (double)1024);
	}

	fclose(rFile);
	fclose(rPatton);

	return result;
}

char* timeToString(struct tm *t)
{
	static char s[20];

	sprintf_s(s, sizeof(s), "%04d-%02d-%02d %02d:%02d:%02d",
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec
		);

	return s;
}


int hwp(char *PATH, _int64 time_create, _int64 time_access, _int64 time_write, _int64 size)
{
	FILE * fp;
	unsigned char fc;
	int offset;
	int result = 0;
	char seg[40] = { 0 };
	offset = fc = 0;
	fp = _fsopen("D:\\hancomtest\\mshtest01_s.hwp", "rb", _SH_DENYWR);

	if (fp == NULL)
	{
		printf("File read error!\n");
		exit(0);
	}

	offset = 0;
	while (1)
	{
		fc = fgetc(fp);
		if (feof(fp) != 0) break;

		if (fc == 'H')
		{
			if (fgetc(fp) == 'W')
			{
				if (fgetc(fp) == 'P')
				{
					offset = ftell(fp);
					offset -= 3;
					break;

				}
				else fseek(fp, -2, SEEK_CUR);
			}
			else fseek(fp, -1, SEEK_CUR);
		}
	}

	printf("fileoffset : %08X\n", offset);

	if (offset != 0)
	{
		fseek(fp, offset, SEEK_SET);
		fread(seg, 12, 1, fp);
		seg[12] = '\0';

		if (strcmp(seg, "HWP Document") == 0)
		{
			fseek(fp, -12, SEEK_CUR);
			fread(seg, 36, 1, fp);
			fc = fgetc(fp);

			if ((fc & 2) == 2) result = 1;
		}
	}

	fclose(fp);
}