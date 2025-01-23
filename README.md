# GVRF

## Getting started

### Prerequisites
- A debian based distribution (did not test others)
- [Boost > 1.82.0](https://www.boost.org/doc/libs/1_85_0/more/getting_started/unix-variants.html)
- OpenSSL (For Ubuntu execute: sudo apt install openssl) and set the OPENSSL_ROOT_DIR system variable to the path of the OpenSSL root folder
This can be done by issuing which openssl and export OPENSSL_ROOT_DIR=/path/to (omit the /openssl at the end)
- CMake (For Ubuntu execute: sudo apt install cmake)
- Build-Essential (For Ubuntu execute: sudo apt install build-essential) This installs gcc and some required headers for C++.
- gmp and gmpxx (For Ubuntu execute: sudo apt install libgmp3-dev)
- autoconf libtool pkg-config (sudo apt install autoconf libtool pkg-config)
- as one command not including boost(apt-get install -y cmake build-essential wget autoconf libgmp3-dev libtool pkg-config openssl )

### How to run the application

1. A bit less user friendly, sorry, but in the root directory of the code (where the readme is) there is a CMakeList.txt. Here, in line 2, you can set a 1 if Privacy Pass should be used, or a 0 if it should not be used. If you set it to 1, then line 3 can be ignored, otherwise a 1 to GVRF_OPT means to use a faster arithmetic backend than GVRF* in the paper, and a 0 means to use the same as Privacy Pass.

2. Execute in the root directory 
```bash
cmake --no-warn-unused-cli \
  -DCMAKE_BUILD_TYPE:STRING=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
  -S. -B./build -G "Unix Makefiles"
``` 
3. and   
```bash 
cmake --build ./build --config Debug --target all -j 18 -- 
``` 
to build the project.

4. Then, create a folder for the TLS certificates with:
```bash
mkdir ./build/cert
```

5. and generate the dummy certificates with: 
```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout ./build/cert/localhost.key -out ./build/cert/localhost.crt -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:*.example.com,IP:127.0.0.1"
```
Client-side peer verification is disabled for this example, so it does not matter which IPs and domains you specify here. (Does not disturb the benchmarks in any way, since peer verification is done beforehand)

6. Now navigate to the build folder /build and you are able to run the actual application with. Always run the server before the client
```bash
 ./gvrf --role <'client' or 'server'> --address <address> --port <port> --threads <threads> --amount <amount> --runs <runs>
```
To reproduce the numbers in the table, we set it up locally by running (you have to specify the actual ip of localhost here), but it also works over the internet:
```bash
  ./gvrf  --role server --address 127.0.0.1 --port 8080 --threads 1 --runs 50 --amount 50
```
This runs the server on port 8080, with 1 thread for the web server as we only have 1 client. "runs" specifies the protocol runs and "amount" the amount of tokens simultaneously generated (amount also runs AT.Expand and AT.Verify 50 times per run).
```bash
 ./gvrf --role client --address 127.0.0.1 --port 8080 --threads 1 --runs 50 --amount 50
```
And this runs the client, where the address, port, runs and amount must be those of the server. The threads parameter is ignored here, and for cryptographic operations the number of threads available (also for the server) are fetched and used for this application. 

### Known bugs
Changing the arithmetic backend in RELIC is sometimes a bit sluggish. Also, sometimes the "easy" arithmetic backend is used instead of gmp-sec, leading to much slower benchmarks. This can be checked by running the application and checking the RELIC configuration at the top for both client and server. Also, when GVRF_OPT is set to 1, the printed arithmetic backend must be X64_ASM_6L.

 This is somewhat arbitrary and does not happen very often. What I did to fix it was sometimes to run cd ... and navigate to the folder again. Also, sometimes I had to delete the build folder and rebuild it. 

Also, sometimes when switching from privacy pass to gvrf or vice versa, the build folder has to be deleted because gmp causes some problems. After deleting it, it works again, but copy the certificate inside the build folder beforehand.
