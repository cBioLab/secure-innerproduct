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
void showMat(std::vector< std::vector<int> > &matrix){
	int m =  matrix.size();
	for(int i = 0; i < m; i++){
		std::vector<int> v = matrix[i];
		int n = v.size();
		for(int j = 0; j <  n; j++){
			std::cout << v[j] <<  " ";
		}
		std::cout << std::endl;
	}
}

void readMat(int &m, int &n, std::string matfile, std::vector< std::vector<int> > &mat)
{
	std::ifstream ifs(matfile.c_str());
	std::string tmp;
	int j = 0;
	char ch;
	ifs >> tmp;
	n = tmp.length();
	std::vector<int> v(n);
	mat.push_back(v);
	for (int i=0;i<n;i++){
		ch = tmp[i];
		mat[j][i] = (ch == '1') ? 1 : 0;
	}
	j++;
	while(!ifs.eof()){
		ifs >> tmp;
		std::vector<int> v(n);
		mat.push_back(v);
		for (int i=0;i<n;i++){
			ch = tmp[i];
			mat[j][i] = (ch == '1') ? 1 : 0;
		}
		j++;
	}
	m = j;
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
}

void init(int &m, int &n,std::vector< std::vector<int> > &mat, std::string matfile){
	SysInit();
	readMat(m, n, matfile, mat);
	std::cout  << m << std::endl;
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

void inner_vector_vector(Elgamal::CipherText &ans,std::vector<Elgamal::CipherText> &c,std::vector<int> &s){
	int i = 0;
	for(std::vector<int>::iterator itr=s.begin();itr!=s.end();i++,itr++){
		Elgamal::CipherText tmp = c[i];
		tmp.mul(*itr);
		ans.add(tmp);
	}
}


//mat should be transposed
void inner_vector_matrix(std::vector<Elgamal::CipherText> &ans,std::vector<Elgamal::CipherText> &v,std::vector< std::vector<int> > &mat){
	int m = mat.size();
	for(int i = 0; i <  m; i++){
		inner_vector_vector(ans[i], v, mat[i]);
	}
}

void plain_inner_product(std::vector<int> &ans, std::vector<int> s, std::vector< std::vector<int> > mat){
	int m = mat.size();
	for(int i = 0; i <  m; i++){
		int j = 0;
		ans[i] = 0;
		for(std::vector<int>::iterator itr=s.begin();itr!=s.end();j++,itr++){
			ans[i]+=mat[i][j]*(*itr);
		}
	}
}



int main(int argc, char **argv){
	try{
		std::string pubfile = "../comm/server/pub.dat";
		std::string queryfile = "../comm/server/query.dat";
		std::string answerfile = "../comm/server/answer.dat";
		std::string paramfile = "../comm/server/param.dat";
		if(argc != 2){
			std::cerr << "Usage: inner_server database_file" << std::endl;
			exit(EXIT_FAILURE);
		}

		std::string matfile = argv[1];

		/*Initialization*/
		int m, n;
		std::vector< std::vector<int> > matrix;
		init(m, n, matrix, matfile);
		std::cout << n << std::endl;

		std::vector<Elgamal::CipherText> vector_enc(n);
		int sock0 = prepSSock();
		int sock = acceptSSock(sock0);

		std::ofstream ofs(paramfile.c_str(), std::ios::binary);
		ofs << m;
		ofs.close();
		sendFile(sock, (char *)paramfile.c_str());
		std::cout << "sent param" << std::endl;
		
		//recv pub key
		//recv vector_enc
		Elgamal::PublicKey pub;
		recvFile(sock,(char *)pubfile.c_str());
		std::ifstream ifs(pubfile.c_str(), std::ios::binary);
		ifs >> pub;
		ifs.close();
		std::cout << "received key" << std::endl;
		recvFile(sock,(char *)queryfile.c_str());
		read_encVec(n, queryfile, vector_enc);
		std::cout << "received query" << std::endl;

		//inner product
		std::vector<int> tmp(m, 0);
		std::vector<Elgamal::CipherText> ans(m);
		encText(tmp,ans,pub);
		inner_vector_matrix(ans,vector_enc,matrix);

		//send ans
		store_encVec(m, answerfile, ans);
		sendFile(sock,(char *)answerfile.c_str());
		std::cout << "sent answer" << std::endl;

		closeSock(sock);
	}catch(std::exception& e){
		printf("ERR %s\n", e.what());
	}
}
