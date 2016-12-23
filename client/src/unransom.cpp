#include "crypto.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include "traverse.hpp"
#include "file.hpp"

//Custom file handler...
void file_handler(const std::string& filepath,const std::string& key,const std::string& iv)
{
	try
	{
		aes_t aes(key,iv);
		std::string cipher;
		if(file_to_string(filepath,cipher)&&string_to_file(aes.decrypt(key),filepath))
			std::cout<<"Unransomed "<<filepath<<std::endl;
		else
			std::cout<<"Error "<<filepath<<std::endl;
	}
	catch(...)
	{
		std::cout<<"Skipping "<<filepath<<std::endl;
	}
}

int main()
{
	try
	{
		std::cout<<"Enter ransom root directory:"<<std::endl;
		std::string ransom_directory;
		if(!std::getline(std::cin,ransom_directory))
			throw std::runtime_error("Invalid ransom root directory.");

		std::cout<<"Enter hex encdoded key:"<<std::endl;
		std::string key;
		if(!(std::cin>>key)||key.size()!=32*2)
			throw std::runtime_error("Invalid key value.");
		key=hex_decode(key);

		std::cout<<"Enter hex encdoded iv:"<<std::endl;
		std::string iv;
		if(!(std::cin>>iv)||iv.size()!=16*2)
			throw std::runtime_error("Invalid key value.");
		iv=hex_decode(iv);

		traverse_files(ransom_directory,key,iv,file_handler);
	}
	catch(std::exception& error)
	{
		std::cout<<"Error: "<<error.what()<<std::endl;
	}
	catch(...)
	{
		std::cout<<"Unknown error occurred."<<std::endl;
	}
	return 0;
}
