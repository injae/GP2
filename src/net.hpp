#include <hm_crypt/eig.hpp>
#include <network/ring.hpp>
#include <hm_crypt/hash.hpp>

#include <range/v3/all.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <serdepp/adaptor/rapidjson.hpp>

#include <fmt/chrono.h>

#include <set>

using namespace simnet::ring;
using namespace hmc;
using namespace ssl;
using namespace ranges;

template<typename T>
T decode(const std::string& data) {
    auto json= nlohmann::json::parse(data);
    return serde::deserialize<T>(json);
}

template<typename T>
std::string encode(const T& data) {
    return serde::serialize<nlohmann::json>(data).dump();
}

//#define DEBUG_MSG // print log message flag

void head_node(Node& net, std::shared_ptr<spdlog::logger> logger, const std::string& message) {
    auto log = [&net, logger](const std::string& fmt) {
        using namespace std::chrono;
        #ifdef DEBUG
        fmt::print("{}\n",fmt);
        #endif
        logger->info("[{}]:{}\n",net.port(), fmt);
        logger->flush();
    };
    fmt::print("head Node\n");
    fmt::print("input start signal\n");
    std::cin.get();
    net.send_all(protocol::config());
    fmt::print("== network setting end ==\n");
    fmt::print("info: head:{}, next:{}, port:{}, prev:{}\n",net.head(), net.next(), net.port(), net.prev());
    //std::string Mi = net.port(); // 노드의 메시지
    std::string Mi = message; // 노드의 메시지

    eig::public_key pk;
    eig::secret_key sk;
    log("generate pk");
    std::string key_cache ="{}-key.json"_format(net.port());
    if(std::filesystem::exists(key_cache)) {
        pk = serde::deserialize<eig::public_key>(serde::parse_file<nlohmann::json>(key_cache));
    } else {
        pk = eig::public_key(2048);
        std::ofstream fs(key_cache);
        fs << serde::serialize<nlohmann::json>(pk).dump();
        fs.close();
    }

    log("generated pk start system");

    log("send pk to all");
    net.send_all(encode(pk));

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);
    sk = eig::secret_key(pk, xi);
    yi = g.exp(xi, p);
    log("spead yi");
    net.send_all(encode(yi));

    Y = yi;
    log("receive yn start");
    for(auto& yn_packet : net.receive_all()) {
        yn_packet.wait();
        auto yn = decode<Bn>(yn_packet.get());
        Y.mul_inplace(yn, p);
    }
    log("receive yn");

    std::vector<eig::cipher> Cn;
    std::set<eig::cipher> _Cn;
    eig::cipher Ci = pk.encrypt(Mi);

    log("receive Cn all start");
    Cn.push_back(Ci);
    for(auto& Cn_packet : net.receive_all()) {
        Cn_packet.wait();
        Cn.push_back(decode<eig::cipher>(Cn_packet.get()));
    }
    log("end");

    for(auto& [ui, vi] : Cn) {
        auto ri = eig::random_r(q);
        auto _ui = ui.mul(g.exp(ri,p),p);
        auto _vi = vi.mul(Y.exp(ri,p),p);
        _Cn.insert({_ui, _vi});
    }
    log("send _Cn next");
    net.send_to(encode(_Cn | to_vector), net.next());

    auto Cn_packet = net.receive_from(net.prev()); Cn_packet.wait();
    log("receive _Cn prev");
    Cn = decode<std::vector<eig::cipher>>(Cn_packet.get());
    log("send Cn all");
    net.send_all(encode(Cn));

    std::vector<Bn> zn;
    std::vector<Bn> wn;
    for(auto& [ui, vi] : Cn) {
        auto zi = ui.exp(sk.x, p).inv(p);
        zn.push_back(zi);
        wn.push_back(vi.mul(zi, p));
    }
    log("send Zn all");
    net.send_all(encode(zn));

    log("receive Zn all");
    std::vector<std::vector<Bn>> Zn;
    for(auto& zi_packet : net.receive_all()) {
        zi_packet.wait();
        Zn.push_back(decode<std::vector<Bn>>(zi_packet.get()));
    }
    log("end");

    std::vector<std::string> _Mn;
    for(auto [i, wi] : wn | views::enumerate) {
        _Mn.push_back(ranges::accumulate(Zn, wi, [i=i, p=p](auto it, auto zi) {
            return it.mul(zi[i], p);
        }).to_string());
    }
    log("_Mn:{}, finish system"_format(_Mn));
}

void node(Node& net, std::shared_ptr<spdlog::logger> logger, const std::string& message) {
    auto log = [&net,logger](const std::string& fmt) {
        using namespace std::chrono;
        #ifdef DEBUG
        fmt::print("{}\n",fmt);
        #endif
        logger->info("[{}]:{}\n",net.port(), fmt);
        logger->flush();
    };

    while(net.is_configure()) {}
    log("== network setting end ==\n");
    log("info: head:{}, next:{}, port:{}, prev:{}\n"_format(net.head(), net.next(), net.port(), net.prev()));
    std::string Mi = message; // Node의 메세지

    eig::public_key pk;
    eig::secret_key sk;

    log("receiving pk from head");
    auto data = net.receive_from(net.head()); data.wait();
    pk = decode<eig::public_key>(data.get());
    log("end");

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);
    sk = eig::secret_key(pk, xi);
    yi = g.exp(xi, p);
    log("spead yi");
    net.send_all(encode(yi));

    Y = yi;
    log("receive yn start");
    for(auto& yn_packet : net.receive_all()) {
        yn_packet.wait();
        auto yn = decode<Bn>(yn_packet.get());
        Y.mul_inplace(yn, p);
    }
    log("end");

    std::vector<eig::cipher> Cn;
    std::set<eig::cipher> _Cn;
    eig::cipher Ci = pk.encrypt(Mi);
    log("send Cn head");
    net.send_to(encode(Ci), net.head());

    log("receive _Cn prev");
    
    auto Cn_packet = net.receive_from(net.prev()); Cn_packet.wait();
    Cn_packet.wait();
    log("end");
    Cn = decode<std::vector<eig::cipher>>(Cn_packet.get());

    for(auto& [ui, vi] : Cn) {
        auto ri = eig::random_r(q);
        auto _ui = ui.mul(g.exp(ri,p),p);
        auto _vi = vi.mul(Y.exp(ri,p),p);
        _Cn.insert({_ui, _vi});
    }
    log("send _Cn next");
    net.send_to(encode(_Cn | to_vector), net.next());

    log("receive _Cn head");
    auto _Cn_packet = net.receive_from(net.head()); _Cn_packet.wait();
    log("end");
    Cn = decode<std::vector<eig::cipher>>(_Cn_packet.get());

    std::vector<Bn> zn;
    std::vector<Bn> wn;
    for(auto& [ui, vi] : Cn) {
        auto zi = ui.exp(sk.x, p).inv(p);
        zn.push_back(zi);
        wn.push_back(vi.mul(zi, p));
    }
    log("send Zn all");
    net.send_all(encode(zn));

    std::vector<std::vector<Bn>> Zn;
    log("receive Zn all");
    for(auto& zi_packet : net.receive_all()) {
        zi_packet.wait();
        Zn.push_back(decode<std::vector<Bn>>(zi_packet.get()));
    }

    fmt::print("[{}]: end\n",net.port());
    log("end");

    std::vector<std::string> _Mn;
    for(auto [i, wi] : wn | views::enumerate) {
        _Mn.push_back(ranges::accumulate(Zn, wi, [i=i, p=p](auto it, auto zi) {
            return it.mul(zi[i], p);
        }).to_string());
    }
    log("_Mn:{}, finish system"_format(_Mn));
}

void start(const std::string& server_port, const std::string& head_port, const std::string& message) {
    std::string server_ip = "localhost";
    auto net = Node(server_port, head_port);

    auto pool = net.configure(server_ip, net.head());
    try {
        auto logger = spdlog::basic_logger_mt("node-{}"_format(net.port()), "net-logs/{}-log.txt"_format(net.port()));
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%n] [%l] %v");

        net.is_head() ? head_node(net, logger, message) : node(net, logger, message);
        if(net.is_head()) {
            fmt::print("wait finish all and input test end\n");
            for(auto&& check : net.receive_all()) { check.wait(); }
            net.send_all("end");
        } else {
            net.send_to("end",net.head());
            net.receive_from(net.head());
        }
    } catch(const spdlog::spdlog_ex& ex) {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    } catch(const std::exception& ex){
        fmt::print("finish\n");
    }
}
