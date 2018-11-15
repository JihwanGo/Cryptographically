#include "Chrome_c.h"

int Crypto_count;
int Compres_count;

int main(int argc, char *argv[])
{
	static clock_t start, end;
	
	system("cls");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	printf("  ■■■   		                                    \n");
	printf(" ■    ■  ■                                          \n");
	printf("■         ■       ■         ■■■    ■■  ■■    ■■■    \n");
	printf("■         ■■■   ■ ■■   ■    ■  ■  ■■  ■  ■     ■   \n");
	printf("■         ■   ■  ■■  ■  ■    ■  ■   ■   ■  ■■■■   \n");
	printf(" ■    ■  ■   ■  ■        ■    ■  ■   ■   ■  ■         \n");
	printf("  ■■■   ■   ■  ■         ■■■   ■        ■   ■■■■   \n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	printf("                 암호화 및 압축 파일 판단 프로그램 [Version 0.1] \n  \n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	printf("                   팀원 : 문성현, 황호성, 고동현, 정광수, 황지환\n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf("                  Copyright (c) 2016 Chrome. All rights reserved \n");

	if (argc == 1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		printf("\n\n");
		printf("┌─[ 도움말 ]────────────────────────┐\n");
		printf("│                                                            │\n");
		printf("│ 탐색 대상의 디렉토리 정보를 함께 입력 하세요.              │\n");
		printf("│                                                            │\n");
		printf("│ ex) \\Chrome_c.exe \"탐색 대상 디렉토리\"                     │\n");
		printf("│                                                            │\n");
		printf("└──────────────────────────────┘\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else if (argc >= 3 || argv[1][strlen(argv[1]) - 1] == '\\')
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		printf("\n\n");
		printf("┌─[ 프로그램 ERROR ]────────────────────┐\n");
		printf("│                                                            │\n");
		printf("│ 탐색 대상의 디렉토리 정보에 문제가 있습니다.               │\n");
		printf("│                                                            │\n");
		printf("│ ex) \\Chrome_c.exe \"탐색 대상 디렉토리\"                     │\n");
		printf("│                                                            │\n");
		printf("└──────────────────────────────┘\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("\n\n");
		printf("┌──────────────────────────────┐\n");
		printf("│                                                            │\n");
		printf("│ 탐색 대상의 디렉토리 이하 모든 파일을 탐색 합니다.         │\n");
		printf("│                                                            │\n");
		printf("│ ex) \\Chrome_c.exe \"탐색 대상 디렉토리\"                     │\n");
		printf("│                                                            │\n");
		printf("└──────────────────────────────┘\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
	}
	system("cls");

	start = clock();
	DirectorySearch(argv[1]);
	end = clock();

	printf("\n");
	printf("┌[ 탐색 완료 ]\n");
	printf("│ \n");
	printf("│ 암호화 파일 %2d개, 압축 파일 %2d개를 탐지 하였습니다.\n", Crypto_count, Compres_count);
	printf("│ \n");
	printf("└ 소요 시간 : %.3lf 초\n\n", (end - start) / (double)1000);

	return 0;
}

