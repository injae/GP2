#include <simnet/simnet.hpp>
#include <asio.hpp>

int main(int argc, char* argv[]) {
    if(argc < 2) { fmt::print("require {server port}\n"); return -1; }

    asio::io_context io_context;
    simnet::client client(io_context);
    client.connect(asio::ip::host_name(), argv[1]);
    client.api()->send("hello");
    client.api()->send("hello world");
    client.api()->send("hello world");
    client.api()->send("hello world");
    client.api()->send("hello world");

    while(true) {}

    return 0;
}
