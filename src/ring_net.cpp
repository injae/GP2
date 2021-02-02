#include "net.hpp"

int main(int argc, char* argv[]) {
    if(argc < 3) { fmt::print(stderr, "require (server port), (head port)\n"); return -1; }
    start(argv[1], argv[2]);
    return 0;
}

