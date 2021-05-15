# 코드 설명
- 구현 로직은는 net.cpp에존재
- node들의 타입은 head_node , node로 2가지로 정의된다.
- head_node를 기준으로 네트워크에 참여하는 로직이다.
- net.cpp 파일의 head_node함수가 head_node의 코드이고 node가 서버에 join하는 node들의 코드이다.
- Message는 각 node의 port로 지정된다.
- 각 node의 log는 build/Release/logs/{port}-log.txt에 저장된다.
- 테스트를 위해서는 head노드와 각 노드들을 실행시켜야되는데 노드의 수가많으면 별도 터미널을 많이 열어야되서 test_script.sh로 노드들을 백드라운드로 실행 시켜준다.
- head_node에서 start를 입력하면 현재까지 등록된 node들과 연산을 수행한다.
- head_node에서 wait finish all이 출력되면 다른노드의 종료를 조금 기다린뒤 end를 입력하면 로그가 저장된다.

# Dependency
- cmake 
- clang (c++ 17 support version)
- git

# Build Script
```shell
mkdir build
cd build
cmake -DUSE_CPPM_PATH=ON -DCMAKE_BUILD_TYPE=Release .. && cmake --build . --config Release --  -j{코어갯수} 
# result -> build/Release/net
```

# Running Script
```shell
# example 3node
# if head node
# net {current port} {head port}
# terminal 1 (pwd: build/Release)
./net 1111 1111

# terminal 2 (pwd: project root)
# test_script {head port} {nodes count}
./test_script.sh 1111 2

# terminal 1
start # process start
# wait finish all 이 출력된다면 조금 기다린뒤 end 호출
end   # wait other nodes

# log file (path: build/Release/logs/*)
```
# 테스트
- 테스트 환경: Macbook 2019 16인치 고급형
- node3: [prev -> next(0.001s), head -> node... -> head (0.024s), success time(0.055s)]
