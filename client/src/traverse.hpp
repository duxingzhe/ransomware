#ifndef TRAVERSE_HPP
#define TRAVERSE_HPP

#include <string>

void traverse_files(const std::string& path,const std::string& key,const std::string& iv,
	void(*handler)(const std::string&,const std::string&,const std::string&));

#endif