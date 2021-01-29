

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
# terminal 1
./net 1111 1111

# terminal 2
./net 1112 1111

# terminal 3
./net 1113 1111


# terminal 1
start
end

```

