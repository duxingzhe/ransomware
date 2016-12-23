#include "traverse.hpp"

#if defined(_WIN32)&&!defined(__CYGWIN__)
	#define _SCL_SECURE_NO_WARNINGS
	#include <windows.h>
#else
	#include <dirent.h>
#endif

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