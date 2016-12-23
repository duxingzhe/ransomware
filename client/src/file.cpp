//http://etutorials.org/Programming/secure+programming/Chapter+2.+Access+Control/2.5+Erasing+Files+Securely/
#include "file.hpp"
#include <fstream>


bool file_to_string(const std::string& filename,std::string& data)
{
	char buffer;
	std::ifstream istr(filename.c_str(),std::ios_base::in|std::ios_base::binary);
	istr.unsetf(std::ios_base::skipws);
	if(!istr)
		return false;
	data="";
	while(istr>>buffer)
		data+=buffer;
	istr.close();
	return true;
}

bool string_to_file(const std::string& data,const std::string& filename)
{
	bool saved=false;
	std::ofstream ostr(filename.c_str(),std::ios_base::out|std::ios_base::binary);
	saved=(bool)(ostr<<data);
	ostr.close();
	return saved;
}

#if defined(_WIN32)&&!defined(__CYGWIN__)
	#define _SCL_SECURE_NO_WARNINGS
	#include <windows.h>
	#include <wincrypt.h>

	#define SPC_WIPE_BUFSIZE 4096

	static BOOL RandomPass(HANDLE hFile, HCRYPTPROV hProvider, DWORD dwFileSize)
	{
	  BYTE  pbBuffer[SPC_WIPE_BUFSIZE];
	  DWORD cbBuffer, cbTotalWritten, cbWritten;

	  if (SetFilePointer(hFile, 0, 0, FILE_BEGIN) == 0xFFFFFFFF) return FALSE;
	  while (dwFileSize > 0) {
		cbBuffer = (dwFileSize > sizeof(pbBuffer) ? sizeof(pbBuffer) : dwFileSize);
		if (!CryptGenRandom(hProvider, cbBuffer, pbBuffer)) return FALSE;
		for (cbTotalWritten = 0;  cbBuffer > 0;  cbTotalWritten += cbWritten)
		  if (!WriteFile(hFile, pbBuffer + cbTotalWritten, cbBuffer - cbTotalWritten,
						 &cbWritten, 0)) return FALSE;
		dwFileSize -= cbTotalWritten;
	  }
	  return TRUE;
	}

	static BOOL PatternPass(HANDLE hFile, BYTE *pbBuffer, DWORD cbBuffer, DWORD dwFileSize) {
	  DWORD cbTotalWritten, cbWrite, cbWritten;

	  if (!cbBuffer || SetFilePointer(hFile, 0, 0, FILE_BEGIN) == 0xFFFFFFFF) return FALSE;
	  while (dwFileSize > 0) {
		cbWrite = (dwFileSize > cbBuffer ? cbBuffer : dwFileSize);
		for (cbTotalWritten = 0;  cbWrite > 0;  cbTotalWritten += cbWritten)
		  if (!WriteFile(hFile, pbBuffer + cbTotalWritten, cbWrite - cbTotalWritten,
						 &cbWritten, 0)) return FALSE;
		dwFileSize -= cbTotalWritten;
	  }
	  return TRUE;
	}

	bool spc_file_wipe(const std::string& filename) {

    HANDLE hFile = CreateFile(filename.c_str(),     // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template

	  BYTE       pbBuffer[SPC_WIPE_BUFSIZE];
	  DWORD      dwCount, dwFileSize, dwIndex, dwPass;
	  HCRYPTPROV hProvider;
	  if(hFile == INVALID_HANDLE_VALUE)
	  return FALSE;

	  static BYTE  pbSinglePats[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	  };
	  static BYTE  pbTriplePats[6][3] = {
		{ 0x92, 0x49, 0x24 }, { 0x49, 0x24, 0x92 }, { 0x24, 0x92, 0x49 },
		{ 0x6d, 0xb6, 0xdb }, { 0xb6, 0xdb, 0x6d }, { 0xdb, 0x6d, 0xb6 }
	  };
	  static DWORD cbPattern = sizeof(pbTriplePats[0]);

	  if ((dwFileSize = GetFileSize(hFile, 0)) == INVALID_FILE_SIZE) return FALSE;
	  if (!dwFileSize) return TRUE;

	  if (!CryptAcquireContext(&hProvider, 0, 0, 0, CRYPT_VERIFYCONTEXT))
		return FALSE;

	  for (dwPass = 0;  dwPass < 4;  dwPass++)
		if (!RandomPass(hFile, hProvider, dwFileSize)) {
		  CryptReleaseContext(hProvider, 0);
		  return FALSE;
		}

	  memset(pbBuffer, pbSinglePats[5], sizeof(pbBuffer));
	  if (!PatternPass(hFile, pbBuffer, sizeof(pbBuffer), dwFileSize)) {
		CryptReleaseContext(hProvider, 0);
		return FALSE;
	  }
	  memset(pbBuffer, pbSinglePats[10], sizeof(pbBuffer));
	  if (!PatternPass(hFile, pbBuffer, sizeof(pbBuffer), dwFileSize)) {
		CryptReleaseContext(hProvider, 0);
		return FALSE;
	  }

	  cbPattern = sizeof(pbTriplePats[0]);
	  for (dwPass = 0;  dwPass < 3;  dwPass++) {
		dwCount   = sizeof(pbBuffer) / cbPattern;
		for (dwIndex = 0;  dwIndex < dwCount;  dwIndex++)
		  CopyMemory(pbBuffer + (dwIndex * cbPattern), pbTriplePats[dwPass],
					  cbPattern);
		if (!PatternPass(hFile, pbBuffer, cbPattern * dwCount, dwFileSize)) {
		  CryptReleaseContext(hProvider, 0);
		  return FALSE;
		}
	  }

	  for (dwPass = 0;  dwPass < sizeof(pbSinglePats);  dwPass++) {
		memset(pbBuffer, pbSinglePats[dwPass], sizeof(pbBuffer));
		if (!PatternPass(hFile, pbBuffer, sizeof(pbBuffer), dwFileSize)) {
		  CryptReleaseContext(hProvider, 0);
		  return FALSE;
		}
	  }

	  for (dwPass = 0;  dwPass < sizeof(pbTriplePats) / cbPattern;  dwPass++) {
		dwCount   = sizeof(pbBuffer) / cbPattern;
		for (dwIndex = 0;  dwIndex < dwCount;  dwIndex++)
		  CopyMemory(pbBuffer + (dwIndex * cbPattern), pbTriplePats[dwPass],
					  cbPattern);
		if (!PatternPass(hFile, pbBuffer, cbPattern * dwCount, dwFileSize)) {
		  CryptReleaseContext(hProvider, 0);
		  return FALSE;
		}
	  }

	  for (dwPass = 0;  dwPass < 4;  dwPass++)
		if (!RandomPass(hFile, hProvider, dwFileSize)) {
		  CryptReleaseContext(hProvider, 0);
		  return FALSE;
		}

	  CryptReleaseContext(hProvider, 0);
	  return TRUE;
	}
#else
	#include <fcntl.h>
	#include <limits.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <unistd.h>
	#include <errno.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>

	#define SPC_WIPE_BUFSIZE 4096

	static int spc_devrand_fd           = -1,
			   spc_devrand_fd_noblock   = -1,
			   spc_devurand_fd          = -1;

	void spc_make_fd_nonblocking(int fd) {
	  int flags;

	  flags = fcntl(fd, F_GETFL);  /* Get flags associated with the descriptor. */
	  if (flags == -1) {
		perror("spc_make_fd_nonblocking failed on F_GETFL");
		exit(-1);
	  }
	  flags |= O_NONBLOCK;
	  /* Now the flags will be the same as before, except with O_NONBLOCK set.
	   */
	  if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("spc_make_fd_nonblocking failed on F_SETFL");
		exit(-1);
	  }
	}

	void spc_rand_init(void) {
	  spc_devrand_fd         = open("/dev/random",  O_RDONLY);
	  spc_devrand_fd_noblock = open("/dev/random",  O_RDONLY);
	  spc_devurand_fd        = open("/dev/urandom", O_RDONLY);

	  if (spc_devrand_fd == -1 || spc_devrand_fd_noblock == -1) {
		perror("spc_rand_init failed to open /dev/random");
		exit(-1);
	  }
	  if (spc_devurand_fd == -1) {
		perror("spc_rand_init failed to open /dev/urandom");
		exit(-1);
	  }
	  spc_make_fd_nonblocking(spc_devrand_fd_noblock);
	}

	unsigned char *spc_rand(unsigned char *buf, size_t nbytes) {
	  ssize_t       r;
	  unsigned char *where = buf;

	  if (spc_devrand_fd == -1 && spc_devrand_fd_noblock == -1 && spc_devurand_fd == -1)
		spc_rand_init(  );
	  while (nbytes) {
		if ((r = read(spc_devurand_fd, where, nbytes)) == -1) {
		  if (errno == EINTR) continue;
		  perror("spc_rand could not read from /dev/urandom");
		  exit(-1);
		}
		where  += r;
		nbytes -= r;
	  }
	  return buf;
	}

	static int write_data(int fd, const void *buf, size_t nbytes) {
	  size_t  towrite, written = 0;
	  ssize_t result;

	  do {
		if (nbytes - written > SSIZE_MAX) towrite = SSIZE_MAX;
		else towrite = nbytes - written;
		if ((result = write(fd, (const char *)buf + written, towrite)) >= 0)
		  written += result;
		else if (errno != EINTR) return 0;
	  } while (written < nbytes);
	  return 1;
	}

	static int random_pass(int fd, size_t nbytes)
	{
	  size_t        towrite;
	  unsigned char buf[SPC_WIPE_BUFSIZE];

	  if (lseek(fd, 0, SEEK_SET) != 0) return -1;
	  while (nbytes > 0) {
		towrite = (nbytes > sizeof(buf) ? sizeof(buf) : nbytes);
		spc_rand(buf, towrite);
		if (!write_data(fd, buf, towrite)) return -1;
		nbytes -= towrite;
	  }
	  fsync(fd);
	  return 0;
	}

	static int pattern_pass(int fd, unsigned char *buf, size_t bufsz, size_t filesz) {
	  size_t towrite;

	  if (!bufsz || lseek(fd, 0, SEEK_SET) != 0) return -1;
	  while (filesz > 0) {
		towrite = (filesz > bufsz ? bufsz : filesz);
		if (!write_data(fd, buf, towrite)) return -1;
		filesz -= towrite;
	  }
	  fsync(fd);
	  return 0;
	}

	int spc_fd_wipe(int fd) {
	  int           count, i, pass, patternsz;
	  struct stat   st;
	  unsigned char buf[SPC_WIPE_BUFSIZE], *pattern;

	  static unsigned char single_pats[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	  };
	  static unsigned char triple_pats[6][3] = {
		{ 0x92, 0x49, 0x24 }, { 0x49, 0x24, 0x92 }, { 0x24, 0x92, 0x49 },
		{ 0x6d, 0xb6, 0xdb }, { 0xb6, 0xdb, 0x6d }, { 0xdb, 0x6d, 0xb6 }
	  };

	  if (fstat(fd, &st) == -1) return -1;
	  if (!st.st_size) return 0;

	  for (pass = 0;  pass < 4;  pass++)
		if (random_pass(fd, st.st_size) == -1) return -1;

	  memset(buf, single_pats[5], sizeof(buf));
	  if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
	  memset(buf, single_pats[10], sizeof(buf));
	  if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;

	  patternsz = sizeof(triple_pats[0]);
	  for (pass = 0;  pass < 3;  pass++) {
		pattern = triple_pats[pass];
		count   = sizeof(buf) / patternsz;
		for (i = 0;  i < count;  i++)
		  memcpy(buf + (i * patternsz), pattern, patternsz);
		if (pattern_pass(fd, buf, patternsz * count, st.st_size) == -1) return -1;
	  }

	  for (pass = 0;  pass < (int)sizeof(single_pats);  pass++) {
		memset(buf, single_pats[pass], sizeof(buf));
		if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
	  }

	  for (pass = 0;  pass < (int)sizeof(triple_pats) / patternsz;  pass++) {
		pattern = triple_pats[pass];
		count   = sizeof(buf) / patternsz;
		for (i = 0;  i < count;  i++)
		  memcpy(buf + (i * patternsz), pattern, patternsz);
		if (pattern_pass(fd, buf, patternsz * count, st.st_size) == -1) return -1;
	  }

	  for (pass = 0;  pass < 4;  pass++)
		if (random_pass(fd, st.st_size) == -1) return -1;
	  return 0;
	}

	bool spc_file_wipe(const std::string& filename)
	{
		FILE * f = fopen(filename.c_str(),"w");
		if(f==0)
			return false;
		return (spc_fd_wipe(fileno(f))==0);
	}

#endif
