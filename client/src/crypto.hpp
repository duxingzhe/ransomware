#ifndef CRYPTO_WRAPPER_HPP
#define CRYPTO_WRAPPER_HPP

#include "../include/cryptopp/osrng.h"
#include "../include/cryptopp/rsa.h"
#include <string>

std::string hex_decode(const std::string& hex);

class aes_t
{
	public:
		aes_t(const std::string& key,const std::string& iv);
		std::string encrypt(const std::string& plain);
		std::string decrypt(const std::string& cipher);

	private:
		std::string key_m;
		std::string iv_m;
};

class rsa_t
{
	public:
		rsa_t(const size_t bits=4096);
		std::string encrypt(const std::string& plain);
		std::string decrypt(const std::string& cipher);
		std::string get_private() const;
		std::string get_public() const;

	private:
		size_t bits_m;
		CryptoPP::AutoSeededRandomPool rng_m;
		CryptoPP::InvertibleRSAFunction params_m;
		CryptoPP::RSA::PrivateKey private_m;
		CryptoPP::RSA::PublicKey public_m;
};

#endif