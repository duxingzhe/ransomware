#ifndef FILE_HPP
#define FILE_HPP

#include <string>

bool file_to_string(const std::string& filename,std::string& data);
bool string_to_file(const std::string& data,const std::string& filename);
bool spc_file_wipe(const std::string& filename);

#endif
