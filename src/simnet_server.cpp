#include <simnet/simnet.hpp>
#include <fmt/format.h>
#include <thread>

int main(int argc, char* argv[]) {
    asio::io_context io_context;
    simnet::server server(io_context, 12345);
    server.accept();
    auto thread = std::thread([&](){ io_context.run(); });

    while(true) {}
    return 0;
}
