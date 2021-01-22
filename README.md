

# Dependency
- cmake 
- clang

# Build Script
```shell
mkdir build
cd build
cmake -DUSE_CPPM_PATH=ON -DCMAKE_BUILD_TYPE=Debug .. && cmake --build . --config Debug --  -j{코어갯수}
```
바이너리파일 build/Debug에 존재
