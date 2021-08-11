#include <simnet/simnet.hpp>
#include <fmt/format.h>
#include <thread>

int main(int argc, char* argv[]) {
    if(argc < 2) { fmt::print("require port number\n"); return -1; }
    asio::io_context io_context;
    //tcp::v4();
    simnet::server server(io_context, std::atoi(argv[1]));
    server.accept();
    auto thread = std::thread([&](){ io_context.run(); });

    while(true) {}
    return 0;
}
