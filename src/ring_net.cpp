#include <hm_crypt/eig.hpp>
#include <network/ring.hpp>
#include <hm_crypt/hash.hpp>
#include <range/v3/all.hpp>
#include <fmt/ranges.h>
#include <set>

using namespace simnet::ring;
using namespace hmc;
using namespace ssl;
using namespace ranges;

template<typename T>
T decode(const std::string& data) {
    auto json = nlohmann::json::parse(data);
    return serde::serialize<T>(json);
}
 template<typename T>
 std::string encode(const T& data) {
     return serde::deserialize<nlohmann::json>(data).dump();
 }

void head_node(Node& net) {
    fmt::print("head Node\n");
    std::string msg; std::cin >> msg;
    net.configure_finish();
    net.send_all(protocal::config());

    while (net.is_configure()) {}
    net.configure_finish();
    fmt::print("== network setting end ==\n");
    fmt::print("info: port:{}, head:{}, next:{}, prev:{}\n",net.port(),net.head(), net.next(), net.prev());
    std::string Mi = net.port();

    fmt::print("start\n");
    eig::public_key pk;
    eig::secret_key sk;

    pk = eig::public_key(2048);
    fmt::print("generated pk:{}\n",pk);
    net.send_all(encode(pk));

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);
    sk = eig::secret_key(pk, xi);
    yi = g.exp(xi, p);
    net.send_all(encode(yi));

    Y = yi;
    for(auto& yn_packet : net.receive_all()) {
        yn_packet.wait();
        auto yn = decode<Bn>(yn_packet.get());
        Y.mul_inplace(yn, p);
    }

    std::vector<eig::cipher> Cn;
    std::set<eig::cipher> _Cn;
    eig::cipher Ci = pk.encrypt(Mi);

    Cn.push_back(Ci);
    for(auto& Cn_packet : net.receive_all()) {
        Cn_packet.wait();
        Cn.push_back(std::move(decode<eig::cipher>(Cn_packet.get())));
    }

    for(auto& [ui, vi] : Cn) {
        auto ri = eig::random_r(q);
        auto _ui = ui.mul(g.exp(ri,p),p);
        auto _vi = vi.mul(Y.exp(ri,p),p);
        _Cn.insert({_ui, _vi});
    }
    net.send_to(encode(_Cn | to_vector), net.next());

    fmt::print("step 4\n");
    auto Cn_packet = net.receive_from(net.prev()); Cn_packet.wait();
    Cn = decode<std::vector<eig::cipher>>(Cn_packet.get());
    net.send_all(encode(Cn));

    std::vector<Bn> zn;
    std::vector<Bn> wn;
    for(auto& [ui, vi] : Cn) {
        auto zi = ui.exp(sk.x, p).inv(p);
        zn.push_back(zi);
        wn.push_back(vi.mul(zi, p));
    }
    net.send_all(encode(zn));

    std::vector<std::vector<Bn>> Zn;
    for(auto& zi_packet : net.receive_all()) {
        zi_packet.wait();
        Zn.push_back(decode<std::vector<Bn>>(zi_packet.get()));
    }

    std::vector<std::string> _Mn;
    for(auto [i, wi] : wn | views::enumerate) {
        _Mn.push_back(ranges::accumulate(Zn, wi, [i=i, p=p](auto it, auto zi) {
            return it.mul(zi[i], p);
        }).to_string());
    }
    fmt::print("_Mn:{}\n",_Mn);
}

void node(Node& net) {
    while (net.is_configure()) {}
    net.configure_finish();
    fmt::print("== network setting end ==\n");
    fmt::print("info: port:{}, head:{}, next:{}, prev:{}\n",net.port(),net.head(), net.next(), net.prev());
    std::string Mi = net.port();

    fmt::print("start\n");
    eig::public_key pk;
    eig::secret_key sk;

    auto data = net.receive_from(net.head()); data.wait();
    pk = decode<eig::public_key>(data.get());
    fmt::print("{}\n",pk);

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);
    sk = eig::secret_key(pk, xi);
    yi = g.exp(xi, p);
    net.send_all(encode(yi));

    Y = yi;
    for(auto& yn_packet : net.receive_all()) {
        yn_packet.wait();
        auto yn = decode<Bn>(yn_packet.get());
        Y.mul_inplace(yn, p);
    }

    std::vector<eig::cipher> Cn;
    std::set<eig::cipher> _Cn;
    eig::cipher Ci = pk.encrypt(Mi);
    net.send_to(encode(Ci), net.head());

    auto Cn_packet = net.receive_from(net.prev());
    Cn_packet.wait();
    Cn = decode<std::vector<eig::cipher>>(Cn_packet.get());

    for(auto& [ui, vi] : Cn) {
        auto ri = eig::random_r(q);
        auto _ui = ui.mul(g.exp(ri,p),p);
        auto _vi = vi.mul(Y.exp(ri,p),p);
        _Cn.insert({_ui, _vi});
    }
    net.send_to(encode(_Cn | to_vector), net.next());

    fmt::print("step 4\n");
    auto _Cn_packet = net.receive_from(net.head()); _Cn_packet.wait();
    Cn = decode<std::vector<eig::cipher>>(_Cn_packet.get());

    std::vector<Bn> zn;
    std::vector<Bn> wn;
    for(auto& [ui, vi] : Cn) {
        auto zi = ui.exp(sk.x, p).inv(p);
        zn.push_back(zi);
        wn.push_back(vi.mul(zi, p));
    }
    net.send_all(encode(zn));

    std::vector<std::vector<Bn>> Zn;
    for(auto& zi_packet : net.receive_all()) {
        zi_packet.wait();
        Zn.push_back(decode<std::vector<Bn>>(zi_packet.get()));
    }

    std::vector<std::string> _Mn;
    for(auto [i, wi] : wn | views::enumerate) {
        _Mn.push_back(ranges::accumulate(Zn, wi, [i=i, p=p](auto it, auto zi) {
            return it.mul(zi[i], p);
        }).to_string());
    }

    fmt::print("_Mn:{}\n",_Mn);
}


int main(int argc, char* argv[]) {
    if(argc < 3) { fmt::print(stderr, "require (server port), (head port)\n"); return -1; }
    std::string server_ip = "localhost";
    auto net = Node(argv[1], argv[2]);

    auto pool = net.configure(server_ip, net.head());

    net.is_head() ? head_node(net) : node(net);


    if(net.is_head()) {
        fmt::print("wait finish all \n");
        std::string msg;
        std::cin >> msg;
    }else {
        while(true){}
    }

    return 0;
}

