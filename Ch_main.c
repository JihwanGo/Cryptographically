#include "Chrome_c.h"

int Crypto_count;
int Compres_count;

int main(int argc, char *argv[])
{
	static clock_t start, end;
	
	system("cls");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	printf("  ����   		                                    \n");
	printf(" ��    ��  ��                                          \n");
	printf("��         ��       ��         ����    ���  ���    ����    \n");
	printf("��         ����   �� ���   ��    ��  ��  ���  ��  ��     ��   \n");
	printf("��         ��   ��  ���  ��  ��    ��  ��   ��   ��  �����   \n");
	printf(" ��    ��  ��   ��  ��        ��    ��  ��   ��   ��  ��         \n");
	printf("  ����   ��   ��  ��         ����   ��        ��   �����   \n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	printf("                 ��ȣȭ �� ���� ���� �Ǵ� ���α׷� [Version 0.1] \n  \n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	printf("                   ���� : ������, Ȳȣ��, ����, ������, Ȳ��ȯ\n\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf("                  Copyright (c) 2016 Chrome. All rights reserved \n");

	if (argc == 1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
		printf("\n\n");
		printf("����[ ���� ]��������������������������������������������������\n");
		printf("��                                                            ��\n");
		printf("�� Ž�� ����� ���丮 ������ �Բ� �Է� �ϼ���.              ��\n");
		printf("��                                                            ��\n");
		printf("�� ex) \\Chrome_c.exe \"Ž�� ��� ���丮\"                     ��\n");
		printf("��                                                            ��\n");
		printf("����������������������������������������������������������������\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else if (argc >= 3 || argv[1][strlen(argv[1]) - 1] == '\\')
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		printf("\n\n");
		printf("����[ ���α׷� ERROR ]������������������������������������������\n");
		printf("��                                                            ��\n");
		printf("�� Ž�� ����� ���丮 ������ ������ �ֽ��ϴ�.               ��\n");
		printf("��                                                            ��\n");
		printf("�� ex) \\Chrome_c.exe \"Ž�� ��� ���丮\"                     ��\n");
		printf("��                                                            ��\n");
		printf("����������������������������������������������������������������\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
		system("cls");
		exit(0);
	}
	else
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("\n\n");
		printf("����������������������������������������������������������������\n");
		printf("��                                                            ��\n");
		printf("�� Ž�� ����� ���丮 ���� ��� ������ Ž�� �մϴ�.         ��\n");
		printf("��                                                            ��\n");
		printf("�� ex) \\Chrome_c.exe \"Ž�� ��� ���丮\"                     ��\n");
		printf("��                                                            ��\n");
		printf("����������������������������������������������������������������\n ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		system("pause");
	}
	system("cls");

	start = clock();
	DirectorySearch(argv[1]);
	end = clock();

	printf("\n");
	printf("��[ Ž�� �Ϸ� ]\n");
	printf("�� \n");
	printf("�� ��ȣȭ ���� %2d��, ���� ���� %2d���� Ž�� �Ͽ����ϴ�.\n", Crypto_count, Compres_count);
	printf("�� \n");
	printf("�� �ҿ� �ð� : %.3lf ��\n\n", (end - start) / (double)1000);

	return 0;
}

