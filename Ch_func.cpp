#include "Chrome_cpp.h"

void EncrypDetecProgram::DirectorySearch(char *PATH)
{
	intptr_t hFile;
	char search_path[MAX_PATH];
	char searched_path[MAX_PATH];
	char option[] = "\\*.*";

	strcpy_s(search_path, sizeof(search_path), PATH);
	strncat_s(search_path, sizeof(search_path), option, strlen(option));

	cout << PATH << endl << endl;		// Ž�� ���丮 ���� ��� !

	hFile = _findfirsti64(search_path, &find_file);

	if (hFile == -1)
	{
		switch (errno)
		{
		case ENOENT:
			cout << "File does not exist." << endl; break;
		case EINVAL:
			cout << "Invalid path name." << endl; break;
		case ENOMEM:
			cout << "Not enough memory or file name too long." << endl; break;
		default:
			cout << "Unknown error." << endl; break;
		}
	}
	else
	{
		do
		{
			if (strcmp(find_file.name, ".") && strcmp(find_file.name, ".."))
			{
				sprintf_s(searched_path, sizeof(searched_path), "%s\\%s", PATH, find_file.name);

				if (filedata.ExeFileExcep(searched_path))	// �������� ���� ����ó��
				{
					if (_access(searched_path, 4)) continue;// ���Ϲ� ������ ������ ���� ��� ����ó��

					if (find_file.attrib & _A_SUBDIR)
					{
						DirectorySearch(searched_path);		// ���丮�ϰ�� ���ο� ���丮�� �̸� ���� �� ����Լ�
						cout << endl;
						continue;
					}

					if (find_file.size == 0) continue;									// ���� ����� 0�� ��� ����ó��

					if (filedata.HwpFileDetec(searched_path, find_file)) continue;		// hwp���� ��ȣȭ Ž��

					if (filedata.MsoffxFileDetec(searched_path, find_file)) continue;	// DOCX, PPTX, XLSX ���� ��ȣȭ Ž��

					if (filedata.EncrypFileDetec(searched_path, find_file)) continue;	// ��Ʈ���� ��ȣȭ���� Ž��

					filedata.CompFileDetec(searched_path, find_file);					// �������� Ž��
				}
			}

		} while (_findnexti64(hFile, &find_file) == 0);

		_findclose(hFile);		// _findfirsti64(), _findnexti64()�� ���� �޸𸮸� ��ȯ
	}
}

bool FileDetec::ExeFileExcep(char *PATH)
{
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	_splitpath_s(PATH, drive, 3, dir, 256, fname, 256, ext, 256);

	if (ext[0] == '.' && ext[1] == 'e' && ext[2] == 'x' && ext[3] == 'e')
	{
		rFile.open(PATH, ios::in | ios::binary);

		if (!rFile.is_open())
		{
			cout << ".exe File open error." << endl;
			exit(0);
		}

		rFile.read(rsig, 2);

		if (rsig[0] == 'M' && rsig[1] == 'Z') // �������� signature MZ �Ǵ�!
		{
			rFile.close();
			return false;
		}
		rFile.close();
	}
	return true;
}

bool FileDetec::HwpFileDetec(char *PATH, _finddatai64_t find_file)
{
	char fc = 0;
	result = false;

	rFile.open(PATH, ios::in | ios::binary);

	if (!rFile.is_open())
	{
		cout << "hwp_ File read error!" << endl;
		exit(0);
	}

	while (1)
	{
		rFile.read(rsig, 16);
		rsig[12] = '\0';

		if (rFile.eof()) break;

		if (strcmp(rsig, "HWP Document") == 0)
		{
			rFile.read(rsig, 16);
			if (rsig[1] != '\0' && rsig[2] != '\0')
			{
				rFile.seekg(-16, rFile.cur);
				continue;
			}

			rFile.seekg(4, rFile.cur);
			rFile.read(&fc, 1);

			if ((fc & 2) == 2) result = true;
			else
			{
				rFile.seekg(-5, rFile.cur);
				continue;
			}
		}
	}

	if (result)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		cout << "��[ ��ȣȭ ���� - (HWP �Ǵ�) ]" << endl;
		cout << "�� ���� ��� : " << PATH << endl;
		cout << "�� ���� ��¥ : " << TimeToString(&t) << endl;
		cout << "�� ���� ũ�� : " << (double)find_file.size / (double)1024 << " KB" << endl << endl;
	}

	rFile.close();
	return result;
}

bool FileDetec::MsoffxFileDetec(char *PATH, _finddatai64_t find_file)
{
	result = false;
	rFile.open(PATH, ios::in | ios::binary);

	if (!rFile.is_open())
	{
		cout << "MS_ File read error!" << endl;
		exit(0);
	}

	rFile.read(rsig, 8);

	if (rsig[0] = '\xD0' && rsig[1] == '\xCF' && rsig[2] == '\x11')
	{
		rFile.seekg(2048, ios::beg);
		rFile.read(rsig, 16);

		if (rsig[0] == '<' && rsig[4] == 'M' && rsig[6] == 'i' && rsig[8] == 'c')
			result = true;

		if (!result)
		{
			rFile.seekg(2304, ios::beg);
			rFile.read(rsig, 16);

			if (rsig[0] == '<' && rsig[4] == 'M' && rsig[6] == 'i' && rsig[8] == 'c')
				result = true;
		}
	}

	if (result)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		cout << "��[ ��ȣȭ ���� - (DOCX, PPTX, XLSX �Ǵ�) ]" << endl;
		cout << "�� ���� ��� : " << PATH << endl;
		cout << "�� ���� ��¥ : " << TimeToString(&t) << endl;
		cout << "�� ���� ũ�� : " << (double)find_file.size / (double)1024 << " KB" << endl << endl;
	}

	rFile.close();
	return result;
}


bool FileDetec::EncrypFileDetec(char *PATH, _finddatai64_t find_file)
{
	long byte_count[256] = { 0 };
	unsigned char buffer[1024] = { 0 };
	int i, n, sigcf, length, psiglen;
	float count, entropy, rPentropy;
	long long kbrn = 0;

	result = false;
	i = n = sigcf = length = psiglen = 0;
	count = entropy = rPentropy = 0.0;

	rFile.open(PATH, ios::in | ios::binary);
	rPatton.open("patton.txt", ios::in);

	memset(byte_count, 0, sizeof(long) * 256);

	if (!rFile.is_open())
	{
		cout << "Encryption files read error!" << endl;
		exit(0);
	}
	if (!rFile.is_open())
	{
		cout << "Patton files read error!" << endl;
		exit(0);
	}

	// Read the while file in parts of 1024
	for (kbrn = (find_file.size / 1024) + 1; kbrn != 0; kbrn--)
	{
		rFile.read((char *)buffer, 1024);

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

	for (int i = 0; i < 256; i++)		// ��Ʈ���� ���
	{
		if (byte_count[i] != 0)
		{
			count = (float)byte_count[i] / (float)length;
			entropy += -count * log2f(count);
		}
	}
	rFile.clear();

	while (1)
	{
		rPatton >> pnum >> psig >> offset >> rPentropy;
		if (rPatton.eof()) break;
		if (pnum[0] != 'E') continue;					// ���� �ĺ���ȣ Ȯ��.

		rFile.seekg(offset, ios::beg);
		rFile.read(rsig, 8);

		psiglen = strlen(psig) - 1;

		for (i = 0, sigcf = 0; i < psiglen; i++)
		{
			if (psig[i] == rsig[i]) sigcf++;
		}

		if (rsig[0] == 'P' && rsig[1] == 'K')			// Office File �������� Zip ��Ʈ���ǿ� ���� ��.
			if (rsig[6] != 0) continue;

		if (sigcf == psiglen) break;
		else if (strcmp(rsig, "EALL") == 0) break;
	}

	if (entropy >= rPentropy) result = true;

	if (result)
	{
		Crypto_count++;
		localtime_s(&t, &find_file.time_write);

		cout << "��[ ��ȣȭ ���� - (��Ʈ���� �Ǵ�) ]" << endl;
		cout << "�� ���� ��� : " << PATH << endl;
		cout << "�� ���� ��¥ : " << TimeToString(&t) << endl;
		cout << "�� ���� ũ�� : " << (double)find_file.size / (double)1024 << " KB" << endl << endl;
	}

	rFile.close();
	rPatton.close();

	return result;
}

bool FileDetec::CompFileDetec(char *PATH, _finddatai64_t find_file)
{
	int i, psiglen, sigcf;
	float rPentropy;
	result = false;
	psiglen = sigcf = 0;

	rFile.open(PATH, ios::in | ios::binary);
	rPatton.open("patton.txt", ios::in);

	if (!rFile.is_open())
	{
		cout << "Compressed files read error!" << endl;
		exit(0);
	}
	if (!rPatton.is_open())
	{
		cout << "Compressed Patton files read error!" << endl;
		exit(0);
	}

	while (1)
	{
		rPatton >> pnum >> psig >> offset >> rPentropy;
		if (rPatton.eof()) break;
		if (pnum[0] != 'C') continue;					// ��������	���� �ĺ���ȣ Ȯ��.

		rFile.seekg(offset, ios::beg);
		rFile.read(rsig, 8);

		psiglen = strlen(psig) - 1;

		for (i = 0, sigcf = 0; i < psiglen; i++)
		{
			if (psig[i] == rsig[i]) sigcf++;
		}

		if (rsig[0] == 'P' && rsig[1] == 'K')		// Office File �������� ����ó��
			if (rsig[6] != 0) continue;

		if (sigcf == psiglen) result = true;
	}

	if (result)
	{
		Compres_count++;
		localtime_s(&t, &find_file.time_write);

		cout << "��[ ���� ���� ]" << endl;
		cout << "�� ���� ��� : " << PATH << endl;
		cout << "�� ���� ��¥ : " << TimeToString(&t) << endl;
		cout << "�� ���� ũ�� : " << (double)find_file.size / (double)1024 << " KB" << endl << endl;
	}

	rFile.close();
	rPatton.close();

	return result;
}

char* FileDetec::TimeToString(tm *t)
{
	static char s[20];

	sprintf_s(s, sizeof(s), "%04d-%02d-%02d %02d:%02d:%02d",
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec
		);

	return s;
}