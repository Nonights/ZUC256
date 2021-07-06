# Fast software implementation with AVX512 instructions of ZUC256

This is the implementation of our paper: **Efficient software Implementation of ZUC-256 (to be published in the Journal of Cryptography)**.

Evaluating on a single server (` 8-cores Intel Xeon Gold 6128 CPU @ 3.40GHz and 128GB of RAM`) with a single thread per party, our project reaches performance speed up to 21Gbs.

## License
This project has been placed in the public domain. As such, you are unrestricted in how you use it, commercial or otherwise. However, no warranty of fitness is provided. If you found this project helpful, feel free to spread the word and cite us.

## Required 
 Our code has been tested on Windows . C++ compiler with C++14 support. There are several library dependencies including:
[1]Compiling with Microsoft Visual Studio 2017 or 2019;
[2]CPU processor needs to support AES-NI instructions and AVX512 instructions.
   
## Building the Project
After cloning project from git
#### Windows:
1. build ZUC256_AVX512 project
2. change the control switch to obtain some results as you want in ZUC256_TEST_AVX512.c (for example: define single_thread = 1, you can verify the correctness of code and evaluate the performance on a single server).
3. run ZUC256_AVX512.sln
 
## Test
Our database is given by the standard. We have 2 functions: 
#### 1. Self Test: 
test ZUC256_AVX512.sln result for ZUC-256 keystream generation algorithm, ZUC-256 keystream based crypt algorithm and ZUC-256 keystream based MAC generation algorithm , shows whether the program computes a right result. This test runs on single_thread = 1:

	./Release/ ZUC256_AVX512.exe 
	
#### 2. Speed Test: 
test result for three functions to obtain optimal performance both in the single and multi-threaded setting. The outputs include the outputxxx.txt file.
 
## Help
For any questions on building or running the project, please send a e-mail to
[Bai Liang]gmu.shmily@gmail.com

Copyright 2021 SDT(CN) Ltd.

## Citation
[1] Design Team. ZUC-256 stream cipher[J]. Journal of Cryptologic Research, 2018, 5(2): 167-179.
[2] BAI L, JIA W Y, ZHU G Z. Efficient software implementations of ZUC-256[J]. Journal of Cryptologic Research, 2021, 8(3):521-536. [DOI: 10.13868/j.cnki.jcr.000455]