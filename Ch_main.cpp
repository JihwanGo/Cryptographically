#include "Chrome_cpp.h"

int Crypto_count;
int Compres_count;

int main(int argc, char *argv[])
{
	static clock_t start, end;

	system("cls");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << "  ����   		                                   " << endl;
	cout << " ��    ��  ��                                        " << endl;
	cout << "��         ��       ��         ����    ���  ���    ����  " << endl;
	cout << "��         ����   �� ���   ��    ��  ��  ���  ��  ��     ��  " << endl;
	cout << "��         ��   ��  ���  ��  ��    ��  ��   ��   ��  �����   " << endl;
	cout << " ��    ��  ��   ��  ��        ��    ��  ��   ��   ��  ��     " << endl;
	cout << "  ����   ��   ��  ��         ����   ��        ��   �����  " << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	cout << "                 ��ȣȭ �� ���� ���� �Ǵ� ���α׷� [Version 0.1] " << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	cout << "                   ���� : ������, Ȳȣ��, ����, ������, Ȳ��ȯ" << endl << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	cout << "                  Copyright (c) 2016 Chrome. All rights reserved" << endl;

	if (argc == 1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		cout << endl << endl;
		cout << "����[ ���� ]��������������������������������������������������" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� Ž�� ����� ���丮 ������ �Բ� �Է� �ϼ���.              ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� ex) \\Chrome_cpp.exe \"Ž�� ��� ���丮\"                   ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "����������������������������������������������������������������\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else if (argc >= 3 || argv[1][strlen(argv[1]) - 1] == '\\')
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		cout << endl << endl;
		cout << "����[ ���α׷� ERROR ]������������������������������������������" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� Ž�� ����� ���丮 ������ ������ �ֽ��ϴ�.               ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� ex) \\Chrome_cpp.exe \"Ž�� ��� ���丮\"                   ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "����������������������������������������������������������������\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		cout << endl << endl;
		cout << "����������������������������������������������������������������" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� Ž�� ����� ���丮 ���� ��� ������ Ž�� �մϴ�.         ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "�� ex) \\Chrome_cpp.exe \"Ž�� ��� ���丮\"                   ��" << endl;
		cout << "��                                                            ��" << endl;
		cout << "����������������������������������������������������������������\n ";
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
	}
	system("cls");

	start = clock();
	EncrypDetecProgram Program(argv[1]);
	end = clock();

	cout << endl;
	cout << "��[ Ž�� �Ϸ� ]" << endl;
	cout << "�� " << endl;
	cout << "�� ��ȣȭ ���� " << Crypto_count << "��, ���� ���� " << Compres_count << "���� Ž�� �Ͽ����ϴ�." << endl;
	cout << "�� " << endl;
	cout << "�� �ҿ� �ð� : " << (end - start) / (double)1000 << "��" << endl << endl;

	return 0;
}

