# **Secure-innerproduct**

C++ implementation of computing inner product between a server's bit vector and a client's bit vector based on additively homomorphic encryption

# Installation Requirements

Create a working directory (e.g., work) and clone the following repositories.

       mkdir work
       cd work
       git clone git://github.com/cBioLab/secure-innerproduct.git
       git clone git://github.com/herumi/xbyak.git
       git clone git://github.com/aistcrypt/Lifted-ElGamal.git
       git clone git://github.com/herumi/mie.git
       git clone git://github.com/herumi/cybozulib.git
       git clone git://github.com/herumi/cybozulib_ext.git

* Xbyak is a prerequisite for optimizing the operations in the finite field on Intel CPUs.
* OpenSSL and libgmp-dev are available via apt-get (or other similar commands).

# Installation
      cd secure-innerproduct
      mkdir bin
      cd src
      make
      
* Before compiling inner_client.cpp, please replace "localhost" of the following line at by your server's hostname.
 std::string hostname = "localhost";

* use tcmalloc (optimal) for Linux; sudo apt-get install libgoogle-perftools-dev

# Usage
    server side:
    cd secure-innerproduct
    mkdir comm/server
    cd bin
    inner_server "database_file"
    
    client side:
    cd secure-innerproduct
    mkdir comm/client
    cd bin
    inner_client "query_file"

# File format

# Prerequisite Files and Libraries for Running Your Application
	* OpenSSL
	* GMP (libgmp-dev)

# Copyright Notice

Copyright (C) 2016, Hiroki Sudo, Masanobu Jimbo, 
All rights reserved.

# License

secure-innerproduct (files in this repository) is distributed under the [BSD 3-Clause License] (http://opensource.org/licenses/BSD-3-Clause "The BSD 3-Clause License").

# Licenses of External Libraries

Licenses of external libraries are listed as follows.

* Lifted-Elgamal: BSD-3-Clause
* cybozulib: BSD-3-Clause
* mie: BSD-3-Clause
* Xbyak: BSD-3-Clause
* MPIR: LGPL2
* OpenSSL: Apache License Version 1.0 + SSLeay License

Software including any of those libraries is allowed to be used for commercial purposes without releasing its source code as long as the regarding copyright statements described as follows are included in the software.

* This product includes software that was developed by an OpenSSL project in order to use OpenSSL toolkit.
* This product includes Lifted-ElGamal, cybozulib, mie, and Xbyak.
* This product includes MPIR.

# Contact Information

* Hiroki Sudo (hsudo108@ruri.waseda.jp)
* Masanobu Jimbo (jimwase@asagi.waseda.jp)

# History

2016/June/16; initial version
