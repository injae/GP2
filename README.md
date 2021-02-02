

# Dependency
- cmake 
- clang
- git

# Build Script
```shell
mkdir build
cd build
cmake -DUSE_CPPM_PATH=ON -DCMAKE_BUILD_TYPE=Debug .. && cmake --build . --config Debug --  -j{코어갯수}
```
바이너리파일 build/Debug에 존재

# Running Script
```shell
# example 3node
# if head node
# net {current port} {head port}
# terminal 1 (pwd: build/Debug)
./net 1111 1111

# terminal 2 (pwd: project root)
# test_script {head port} {nodes count}
./test_script.sh 1111 2



# terminal 1
start # process start
end   # wait other nodes

```
# RESULT
- node3: [prev -> next(0.001s), head -> node... -> head (0.024s), success time(0.055s)]

