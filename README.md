# 코드 설명
- 구현1 로직은는 net.cpp에존재
- 구현2 로직은는 net2.cpp에존재
- 각 node의 log는 build/Release/net{project}-logs/{port}-log.txt에 저장된다.
- 테스트를 위해서는 head노드와 각 노드들을 실행시켜야되는데 노드의 수가많으면 별도 터미널을 많이 열어야되서 test_script.sh로 노드들을 백드라운드로 실행 시켜준다.

# Dependency
- cmake 
- clang (c++ 17 support version)
- git

# Build Script
```shell
mkdir build
cd build
cmake -DUSE_CPPM_PATH=ON -DCMAKE_BUILD_TYPE=Release .. && cmake --build . --config Release --  -j{코어갯수} 
# result -> build/Release/net , build/Release/net2
```

# 구현1 Running Script
```shell
# example 3node
# if head node
# net {current port} {head port}
# terminal 1 (pwd: build/Release)
./net  1111 1111 "message"

# terminal 2 (pwd: project root)
# test_script {head port} {nodes count}
./test_script.sh 1111 100

# terminal 1
# input some text
# log file (path: build/Release/net-logs/*)
```


# 구현2 Running Script
```shell
# example 3node
# if head node
# net {current port} {head port}
# terminal 1 (pwd: build/Release)
./net2 1111 1111 "message"

# terminal 2 (pwd: project root)
# test_script {head port} {nodes count}
./test_script2.sh 1111 100

# terminal 1
# input some text
# log file (path: build/Release/net2-logs/*)
```
