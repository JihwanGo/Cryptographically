#include "Chrome_cpp.h"

int Crypto_count;
int Compres_count;

int main(int argc, char *argv[])
{
	static clock_t start, end;

	system("cls");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << "  ■■■   		                                   " << endl;
	cout << " ■    ■  ■                                        " << endl;
	cout << "■         ■       ■         ■■■    ■■  ■■    ■■■  " << endl;
	cout << "■         ■■■   ■ ■■   ■    ■  ■  ■■  ■  ■     ■  " << endl;
	cout << "■         ■   ■  ■■  ■  ■    ■  ■   ■   ■  ■■■■   " << endl;
	cout << " ■    ■  ■   ■  ■        ■    ■  ■   ■   ■  ■     " << endl;
	cout << "  ■■■   ■   ■  ■         ■■■   ■        ■   ■■■■  " << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	cout << "                 암호화 및 압축 파일 판단 프로그램 [Version 0.1] " << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	cout << "                   팀원 : 문성현, 황호성, 고동현, 정광수, 황지환" << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	cout << "                  Copyright (c) 2016 Chrome. All rights reserved" << endl;

	if (argc == 1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		cout << endl << endl;
		cout << "┌─[ 도움말 ]────────────────────────┐" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ 탐색 대상의 디렉토리 정보를 함께 입력 하세요.              │" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ ex) \\Chrome_cpp.exe \"탐색 대상 디렉토리\"                   │" << endl;
		cout << "│                                                            │" << endl;
		cout << "└──────────────────────────────┘\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else if (argc >= 3 || argv[1][strlen(argv[1]) - 1] == '\\')
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		cout << endl << endl;
		cout << "┌─[ 프로그램 ERROR ]────────────────────┐" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ 탐색 대상의 디렉토리 정보에 문제가 있습니다.               │" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ ex) \\Chrome_cpp.exe \"탐색 대상 디렉토리\"                   │" << endl;
		cout << "│                                                            │" << endl;
		cout << "└──────────────────────────────┘\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		cout << endl << endl;
		cout << "┌──────────────────────────────┐" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ 탐색 대상의 디렉토리 이하 모든 파일을 탐색 합니다.         │" << endl;
		cout << "│                                                            │" << endl;
		cout << "│ ex) \\Chrome_cpp.exe \"탐색 대상 디렉토리\"                   │" << endl;
		cout << "│                                                            │" << endl;
		cout << "└──────────────────────────────┘\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
	}
	system("cls");

	start = clock();
	EncrypDetecProgram Program(argv[1]);
	end = clock();

	cout << endl;
	cout << "┌[ 탐색 완료 ]" << endl;
	cout << "│ " << endl;
	cout << "│ 암호화 파일 " << Crypto_count << "개, 압축 파일 " << Compres_count << "개를 탐지 하였습니다." << endl;
	cout << "│ " << endl;
	cout << "└ 소요 시간 : " << (end - start) / (double)1000 << "초" << endl << endl;

	return 0;
}

