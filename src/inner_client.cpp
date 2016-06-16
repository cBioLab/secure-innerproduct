/*
this uses 
git://github.com/aistcrypt/Lifted-ElGamal.git
git://github.com/herumi/xbyak.git
git://github.com/herumi/mie.git
git://github.com/herumi/cybozulib.git
git://github.com/herumi/cybozulib_ext.git

Please see https://github.com/aistcrypt/Lifted-ElGamal for installation.

Jimbo Masanobu, Sudo Hiroki
*/

#include <cybozu/option.hpp>
#include <iostream>
#include <fstream>
#include <cybozu/random_generator.hpp>
#include <cybozu/crypto.hpp>
#include <stdlib.h>
#include <mie/fp.hpp>
#include <mie/gmp_util.hpp>
#include <mie/elgamal.hpp>
#include <mie/ecparam.hpp>
#include "comm.h"

#if defined(_WIN64) || defined(__x86_64__)
	#define USE_MONT_FP
#endif
#ifdef USE_MONTFP
#include <mie/mont_fp.hpp>
typedef mie::MontFpT<3> Fp;
#else
typedef mie::FpT<mie::Gmp> Fp;
#endif

struct ZnTag;

typedef mie::EcT<Fp> Ec;
typedef mie::FpT<mie::Gmp, ZnTag> Zn; // use ZnTag because Zn is different class with Fp
typedef mie::ElgamalT<Ec, Zn> Elgamal;


cybozu::RandomGenerator rg;

void SysInit()
{
	const mie::EcParam& para = mie::ecparam::secp192k1;
	Zn::setModulo(para.n);
	Fp::setModulo(para.p);
	Ec::setParam(para.a, para.b);
}

void showVec(std::vector<int> &v){
		std::cout << "vec : ";
		for(std::vector<int>::iterator itr=v.begin();itr!=v.end();itr++) std::cout << *itr << " ";
		std::cout << std::endl;
}

void readVec(int  &n, std::string vecfile, std::vector<int> &v){
	std::ifstream ifs(vecfile.c_str());
	std::string tmp;
	ifs >> tmp;
	n = tmp.length();
	v.resize(n);
	char ch;
	for (int i=0;i<n;i++){
		ch = tmp[i];
		v[i] = (ch == '1') ? 1 : 0;
	}
}

void read_encVec(int n, std::string encvecfile, std::vector<Elgamal::CipherText> &vector_enc)
{
	std::ifstream ifs(encvecfile.c_str(), std::ios::binary);
	for (int i=0;i<n;i++){
		ifs >> vector_enc[i];
	}
}

void store_encVec(int n, std::string encvecfile, std::vector<Elgamal::CipherText> &vector_enc)
{
	std::ofstream ofs(encvecfile.c_str(), std::ios::binary);
	for (int i=0;i<n;i++){
		ofs << vector_enc[i] << std::endl;
	}
	ofs.close();
}

void init(int &n, std::vector<int> &v, std::string vecfile){
	SysInit();
	readVec(n, vecfile, v);
}

void makeKey(Elgamal::PrivateKey &prv, int maxRange){
		const mie::EcParam& para = mie::ecparam::secp192k1;
		const Fp x0(para.gx);
		const Fp y0(para.gy);
		const Ec P(x0, y0);
		const size_t bitLen = Zn(-1).getBitLen();
		prv.init(P, bitLen, rg);
		prv.setCache(0, maxRange); //cache
}

void checkKey(const Elgamal::PrivateKey &prv,const Elgamal::PublicKey &pub){
	std::cout << "privateKey : " << prv << std::endl;
	std::cout << "publicKey : " << pub << std::endl;
}

void encText(std::vector<int> &f,std::vector<Elgamal::CipherText> &c,const Elgamal::PublicKey &pub){
	Elgamal::CipherText ct;
	c.resize(f.size());
	int i = 0;
	for(std::vector<int>::iterator itr=f.begin();itr!=f.end();i++,itr++){
		pub.enc(ct,*itr, rg);
		c[i] = ct;
	}
}


int main(int argc, char **argv){
	try{
		std::string pubfile = "../comm/client/pub.dat";
		std::string queryfile = "../comm/client/query.dat";
		std::string answerfile = "../comm/client/answer.dat";
		std::string paramfile = "../comm/client/param.dat";
		std::string hostname = "localhost";
		if(argc != 2){
			std::cerr << "Usage: inner_client query_file" << std::endl;
			exit(EXIT_FAILURE);
		}

		std::string vecfile = argv[1];

		/*Initialization*/
		int n, m;
		std::vector<int> vector;
		init(n, vector, vecfile);
		std::cout << n << std::endl;

		int sock = prepCSock((char *)hostname.c_str());
		recvFile(sock,(char *)paramfile.c_str());
		std::ifstream ifs(paramfile.c_str(), std::ios::binary);
		ifs >> m;
		ifs.close();
		std::cout << "received param " << m << std::endl;


		//makeKey
		Elgamal::PrivateKey prv;
		int maxRange = n;
		makeKey(prv, maxRange);
		std::cout << "created key" << std::endl;
		const Elgamal::PublicKey& pub = prv.getPublicKey();
		std::ofstream ofs(pubfile.c_str(), std::ios::binary);
		ofs << pub;
		ofs.close();
		sendFile(sock,(char *)pubfile.c_str());
		std::cout << "sent key" << std::endl;


		//enc
		std::cout << "encrypting query" << std::endl;
		std::vector<Elgamal::CipherText> vector_enc;
		encText(vector,vector_enc,pub);
		store_encVec(n, queryfile, vector_enc);
		sendFile(sock,(char *)queryfile.c_str());

		//recv ans
		//read ans
		std::vector<Elgamal::CipherText> ans(m);
		recvFile(sock,(char *)answerfile.c_str());
		std::cout << "received answer" << std::endl;
		read_encVec(m, answerfile, ans);

		//dec
		int len = ans.size();
		for(int i = 0; i < len; i++){
			int dec_tmp = prv.dec(ans[i]);
			std::cout << dec_tmp << " ";
		}

		closeSock(sock);

		std::cout << std::endl;

	}catch(std::exception& e){
		printf("ERR %s\n", e.what());
	}
}
