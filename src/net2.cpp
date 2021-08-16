#include "hm_crypt/eig.hpp"
#include "hm_crypt/hash.hpp"
#include "network/ring.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <serdepp/adaptor/rapidjson.hpp>
#include <serdepp/adaptor/nlohmann_json.hpp>
#include <random>

#include <filesystem>
#include <queue>

using namespace hmc;
using namespace ssl;
using namespace simnet::ring;
using namespace ranges;

struct cipher {
    DERIVE_SERDE(cipher,(&Self::s, "s")(&Self::t, "t"))
    Bn s;
    Bn t;
    bool operator<(const cipher& rhs) const { return s < rhs.s; }
};

struct send_one {
    DERIVE_SERDE(send_one, (&Self::check, "check_"))
    bool check;
};

//template<typename T>
//T decode(const std::string& data) {
//    auto json= nlohmann::json::parse(data);
//    return serde::deserialize<T>(json);
//}
//
//template<typename T>
//std::string encode(const T& data) {
//    return serde::serialize<nlohmann::json>(data).dump();
//}

template<typename T>
T decode(const std::string& data) {
    rapidjson::Document doc;
    doc.Parse(data.c_str());
    return serde::deserialize<T>(doc);
}

template<typename T>
std::string encode(const T& data) {
    using namespace rapidjson;
    auto doc = serde::serialize<rapidjson::Document>(data);
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

std::vector<u_int8_t> expand_bytes(std::vector<u_int8_t> data, size_t length) {
    std::vector<uint8_t> buffer(length, 0);
    for(auto rit = data.rbegin(), brit = buffer.rbegin(); rit != data.rend(); ++rit, ++brit) {
        *brit = *rit;
    }
    return buffer;
}


void print_bytes(std::vector<uint8_t>& vec) {
    for(auto& it : vec) { fmt::print("{},",it);}
    fmt::print("\n==\n");
}


template<typename T, typename T2>
std::vector<u_int8_t> append_bytes(T& a, T2& b) {
    T buffer = a;
    buffer.reserve(a.size()+b.size());
    for(auto& it: b) { buffer.push_back(it); }
    return buffer;
}

template<typename T>
std::pair<std::vector<u_int8_t>, std::vector<u_int8_t>> split_bytes(T&& vec, size_t point) {
    std::vector<uint8_t> first = vec, second(vec.begin()+236, vec.end());
    first.erase(first.begin()+point, first.end());
    return {first, second}; 
}


void work(Node& net, std::shared_ptr<spdlog::logger> logger, const std::string& message) {
    auto log = [&net, logger](const std::string& fmt) {
        using namespace std::chrono;
        fmt::print("{}\n",fmt);
        logger->info("[{}]:{}\n",net.port(), fmt);
        logger->flush();
    };

    Bn Wi(message);

    fmt::print("== network setting end ==\n");
    fmt::print("info: head:{}, next:{}, port:{}, prev:{}\n",net.head(), net.next(), net.port(), net.prev());

    log("#Key Generate..");
    eig::secret_key sk;
    eig::public_key pk;
    std::string key_cache ="{}-key.json"_format(net.port());
    if(std::filesystem::exists(key_cache)) {
        pk = serde::deserialize<eig::public_key>(serde::parse_file<nlohmann::json>(key_cache));
    } else {
        pk = eig::public_key(2048);
        std::ofstream fs(key_cache);
        fs << serde::serialize<nlohmann::json>(pk).dump();
        fs.close();
    }
    log("#Step 1");

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);
    sk = eig::secret_key(pk, xi);
    Y = yi = g.exp(xi, p);

    log("broadcast yi");
    net.send_all(encode(yi));

    log("Y <- yi * yi-1 ... y0");
    for(auto& yn_i : net.receive_all()) {
        yn_i.wait();
        auto yn = decode<Bn>(yn_i.get());
        Y.mul_inplace(yn, p);
    }

    log("#Step 2");
    assert(Wi.bit_size() <= 1888);//< 236 /*1888bit*/);
    auto n = net.size()+1;
    auto l = static_cast<size_t>(std::log(n)); if(l < 3) l = 3;
    log("l = {} = log{}"_format(l, n));

    log("Gen A");
    auto wi = expand_bytes(Wi.to_bytes(), 236);
    assert(Wi == Bn(wi));

    std::vector<std::vector<uint8_t>> a_alpha_n;
    std::vector<uint8_t> al(236,0);
    auto alpha_size = l-1;
    auto range = wi.size() / alpha_size;
    auto remain = wi.size() % alpha_size; 
    auto alphai = sha1::hash(eig::random_r(p).to_hex());

    for(int i = 0; i < alpha_size; ++i) {
        std::vector<uint8_t> buf(wi.size(), 0);
        for(int j = 0; j < range; ++j) { auto idx = i*range+j;  buf[idx] = wi[idx]; }
        if(i+1 == alpha_size) {
            for (int j = 0; j < remain; ++j) {
                auto idx = (i+1)*range+j; buf[idx] = wi[idx];
            }
        }
        a_alpha_n.push_back(append_bytes(buf, alphai));
        //std::transform(al.begin(), al.end(), buf.begin(), al.begin(), std::bit_xor<uint8_t>());
    }

    std::vector<cipher> datas;
    for(auto& a_alpha : a_alpha_n) {
        Bn si, ti, bi = eig::random_r(p);
        cipher cipher;
        cipher.s = g.exp(bi, p);
        cipher.t = Bn(a_alpha).mul(Y.exp(bi, p),p);
        datas.emplace_back(cipher);
    }

    std::vector<std::string> keys;
    for(auto& [key, _] : net.sessions()) { keys.push_back(key); }
    sort(keys);

    log("#Step3");
    std::random_device rd;
    std::uniform_int_distribution<int> rand_gen(0, keys.size()-1);

    std::priority_queue<std::string> J;
    for(int i = 0; i < datas.size()-1; ++i) { J.push(keys[rand_gen(rd)]); }
    log("J[0]:{}"_format(J.top()));

    log("send random node");
    int i = 1;
    for(auto& key : keys) { 
        send_one proto;
        if(!J.empty() && key == J.top()) { J.pop(); proto.check = true ; }
        else                             {          proto.check = false; }
        net.send_to(encode(proto), key); // brodcast
        if(proto.check) { net.send_to(encode(datas[i++]), key); }
    }

    log("receive random node");
    std::vector<cipher> shuffle_set;
    shuffle_set.push_back(datas[0]);
    for(auto& [port, check] : net.receive_all_with_port()) {
        check.wait();
        if(decode<send_one>(check.get()).check) {
            auto cipher_future = net.receive_from(port);
            cipher_future.wait();
            shuffle_set.push_back(decode<cipher>(cipher_future.get()));
        }
    }

    log("[{}]:l={}"_format(net.port(), shuffle_set.size()));
    log("suffle");
    std::sort(shuffle_set.begin(), shuffle_set.end());

    log("#Step3.4");
    auto gamma = eig::random_r(p);
    for(auto& [u ,v] : shuffle_set) {
        u = u.mul(g.exp(gamma, p), p);
        v = v.mul(Y.exp(gamma, p), p);
    }

    log("#Step5");
    for(int i = 0; i <= net.size(); ++i) {
        fmt::print("{}->[{}]\n", shuffle_set.size(),net.next());
        net.send_to(encode(shuffle_set), net.next());

        auto future = net.receive_from(net.prev()); future.wait();
        shuffle_set= decode<std::vector<cipher>>(future.get());

        fmt::print("{}<-[{}]\n", shuffle_set.size(), net.prev());
        for(auto& [u ,v] : shuffle_set) {
            v = v.mul(u.exp(xi,p).inv(p), p);
        }
    }
    net.send_all(encode(shuffle_set));
    for(auto& f : net.receive_all()) {
        f.wait();
        auto buf = decode<decltype(shuffle_set)>(f.get());
        shuffle_set.insert(shuffle_set.end(), buf.begin(), buf.end());
    }

    for(auto& [_u ,shf] : shuffle_set) {
        auto [ai, alpha] = split_bytes(shf.to_bytes(), 236);
        print_bytes(ai); print_bytes(alpha);
        for(auto& a_alpha : a_alpha_n) {
            print_bytes(a_alpha);
            auto bn = Bn(a_alpha);
            if(shf == bn) fmt::print("find\n");
        }
        fmt::print("----\n");
    }

    fmt::print("Result: {}\n",shuffle_set.size());
    
    log("Finish");
}

void head_node(Node& net, std::shared_ptr<spdlog::logger> logger, const std::string& message) {
    fmt::print("input start signal\n");
    std::cin.get();
    net.send_all(protocol::config());
    work(net, logger, message);
}

void node(Node &net, std::shared_ptr<spdlog::logger> logger, const std::string &message) {
    fmt::print("wait start signal...\n");
    while(net.is_configure()) {}
    work(net, logger, message);
}

int main(int argc, char *argv[])
{
    if(argc < 3) { fmt::print(stderr, "require (server port), (head port)\n"); return -1; }
    std::string server_port(argv[1]), head_port(argv[2]), message(argv[3]);

    std::string server_ip = "localhost";
    auto net = Node(server_port, head_port);

    auto pool = net.configure(server_ip, net.head());
    try {
        auto logger = spdlog::basic_logger_mt("node-{}"_format(net.port()), "logs/{}-log.txt"_format(net.port()));

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
    }
    //catch(const std::exception& ex){
    //    fmt::print("finish: {}\n",ex.what());
    //}
    

    
    return 0;
}
