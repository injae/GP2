#include <simnet/simnet.hpp>
#include <asio.hpp>

int main(int argc, char* argv[]) {
    asio::io_context io_context;
    simnet::client client(io_context);
    client.connect(asio::ip::host_name(), "12345");
    client.api()->send("hello");
    client.api()->send("hello world");
    client.api()->send("hello world");
    client.api()->send("hello world");
    client.api()->send("hello world");

    return 0;
}
