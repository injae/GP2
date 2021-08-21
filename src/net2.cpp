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

#define __debug

struct cipher {
    DERIVE_SERDE(cipher,(&Self::s, "s")(&Self::t, "t"))
    Bn s;
    Bn t;
    bool operator<(const cipher& rhs) const { return s < rhs.s; }
};

template<class T>
struct send_one {
    DERIVE_SERDE(send_one, (&Self::value, "value"))
    std::optional<std::vector<T>> value;
};


template<typename T>
T decode(const std::string& data) {
    auto json= nlohmann::json::parse(data);
    return serde::deserialize<T>(json);
}

template<typename T>
std::string encode(const T& data) {
    return serde::serialize<nlohmann::json>(data).dump();
}

//template<typename T>
//T decode(const std::string& data) {
//    rapidjson::Document doc;
//    doc.Parse(data.c_str());
//    return serde::deserialize<T>(doc);
//}
//
//template<typename T>
//std::string encode(const T& data) {
//    using namespace rapidjson;
//    auto doc = serde::serialize<rapidjson::Document>(data);
//    StringBuffer buffer;
//    Writer<StringBuffer> writer(buffer);
//    doc.Accept(writer);
//    return buffer.GetString();
//}

std::vector<u_int8_t> expand_bytes(std::vector<u_int8_t> data, size_t length) {
    std::vector<uint8_t> buffer(length, 0);
    for(auto rit = data.rbegin(), brit = buffer.rbegin(); rit != data.rend(); ++rit, ++brit) {
        *brit = *rit;
    }
    return buffer;
}


void print_bytes(const std::string& tag, std::vector<uint8_t> vec) {
    fmt::print("{}: ",tag);
    for(auto& it : vec) { fmt::print("{}, ", it); }
    fmt::print("\n==\n");
}

template<typename T>
inline T wait_get(std::future<T>& value) { value.wait();  return value.get(); }


template<typename T, typename T2>
std::vector<u_int8_t> append_bytes(T& a, T2& b) {
    T buffer = a;
    buffer.reserve(a.size()+b.size());
    for(auto& it: b) { buffer.push_back(it); }
    return buffer;
}

constexpr std::size_t p_len = 2048;                             //! modulus size
constexpr std::size_t tag_len = 160;                            //! hash output size
constexpr std::size_t msg_len = p_len - tag_len;            //! message length in bits
constexpr std::size_t msg_len_bytes = msg_len / 8;              //! message length in bytes

//constexpr std::size_t p_len = 16;                            //! modulus size
//constexpr std::size_t tag_len = 8;                           //! hash output size
//constexpr std::size_t msg_len = p_len - tag_len;         //! message length in bits
//constexpr std::size_t msg_len_bytes = msg_len / 8;           //! message length in bytes

template<typename T>
std::pair<std::vector<u_int8_t>, std::vector<u_int8_t>> split_bytes(T&& vec, size_t point) {
    std::vector<uint8_t> first = vec, second(vec.begin()+msg_len_bytes, vec.end());
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
#ifdef __debug
    print_bytes("original message: ", Wi.to_bytes());
#endif

    fmt::print("== network setting end ==\n");
    fmt::print("info: head:{}, next:{}, port:{}, prev:{}\n",net.head(), net.next(), net.port(), net.prev());

    log("#Key Generate..");
    eig::secret_key sk;
    eig::public_key pk;
    std::string key_cache ="{}-key.json"_format(net.port());
    if(std::filesystem::exists(key_cache)) {
        pk = serde::deserialize<eig::public_key>(serde::parse_file<nlohmann::json>(key_cache));
    } else {
        pk = eig::public_key(p_len);
        std::ofstream fs(key_cache);
        fs << serde::serialize<nlohmann::json>(pk).dump();
        fs.close();
    }
    log("#Step 1");

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);     //! 1 < xi < q - 1
    sk = eig::secret_key(pk, xi);
    yi = g.exp(xi, p);
    Y = yi;
    fmt::print("{}\n",yi.to_dec());

    log("broadcast yi");
    net.send_all(encode(yi));

    log("Y <- yi * yi-1 ... y0");
    for(auto& yn_i : net.receive_all()) {
        auto yn = decode<Bn>(wait_get(yn_i));
        Y = Y.mul(yn, p);
    }
    fmt::print("Y:{}\n",Y.to_dec());

    log("#Step 2");
    assert(Wi.bit_size() <= msg_len);   //! |Wi| <= 1024 - 160 = 864

    auto n = net.size()+1;
    auto l = static_cast<size_t>(std::log(n)); if(l < 3) l = 3;
    log("l = {} = log{}"_format(l, n));

    log("Gen A");
    auto wi = expand_bytes(Wi.to_bytes(), msg_len_bytes);
    assert(Wi == Bn(wi));
    fmt::print("{}\n",wi);
    fmt::print("pk: {}\n",pk);
    fmt::print("sk: {}\n",sk);

#if false
    std::vector<uint8_t> al(msg_len_bytes, 0);
    auto alpha_size = l-1;
    auto range = wi.size() / alpha_size;
    auto remain = wi.size() % alpha_size; 

    for(int i = 0; i < alpha_size; ++i) {
        std::vector<uint8_t> buf(wi.size(), 0);
        for(int j = 0; j < range; ++j) { auto idx = i*range+j;  buf[idx] = wi[idx]; }
        if(i+1 == alpha_size) {
            for (int j = 0; j < remain; ++j) {
                auto idx = (i+1)*range+j; buf[idx] = wi[idx];
            }
        }
        a_alpha_n.push_back(append_bytes(buf, alphai)); // <== a_alpha = (ai||alpha)
        //std::transform(al.begin(), al.end(), buf.begin(), al.begin(), std::bit_xor<uint8_t>());
    }
#endif
    std::vector<std::vector<uint8_t>> a_alpha_n;
    auto alphai = sha1::hash(eig::random_r(q).to_hex());    //! alpha_i

    ssl::Bn a_l(0);
    std::vector<ssl::Bn> vec_ai;                            //! (a_1,a_2,...,a_l)
    vec_ai.resize(l);
    fmt::print("{}\n",alphai);

#ifdef _debug
    //assert(tag_len / 8 == sizeof(alphai) * sizeof(unsigned char));
    std::string str;
    for (int i = 0 ; i < tag_len / 8; i++) {
        char alpha_i[10] = {0};
        sprintf(alpha_i, "%02x", alphai[i]);
        str += std::string(alpha_i);
    }
    std::cout << "alpha_i: " << str << std::endl;
#endif
    for (int i = 0; i < l; i++) {
        vec_ai[i] = std::stoi(net.port());
    }

    //! secret sharings
    //for (int i = 0; i <= l - 1; i++) {
    //    ssl::Bn a_i;     
    //    a_i.random_inplace(msg_len);                                   
    //    vec_ai[i] = a_i;                                    //! (a_1,a_2,...)
    //    a_l = a_l^a_i;                                //! a_l = a_1+a_2+...+a_{l-1}
    //}
    //a_l = a_l^Wi;                                     //! a_l = a_l+w_i = a_1+...+a_{l-1}+w_i
    //vec_ai[l-1] = a_l;    

    //for (int i = 0; i < l; i++) {
    //    std::vector<uint8_t> buf(msg_len_bytes, 0);
    //    buf = vec_ai[i].to_bytes();        
    //    //! a_alpha = (ai||alpha)
    //    a_alpha_n.push_back(append_bytes(buf, alphai)); 
    //    fmt::print("a_alpha_i: {},",append_bytes(buf, alphai));
    //}
    fmt::print("\n");
    for(auto it : vec_ai) {
        a_alpha_n.push_back(it.to_bytes());
        fmt::print("a_alpha_i: {},",it.to_bytes());
    }
    fmt::print("\n");

    std::vector<cipher> datas;
    for(auto& a_alpha : a_alpha_n) {
        Bn si, ti, bi = eig::random_r(q);
        fmt::print("bi:{}\n",bi.to_hex());
        cipher cipher;
        cipher.s = g.exp(bi, p);                        //! g^{\beta_i}
        cipher.t = Bn(a_alpha).mul(Y.exp(bi, p),p);     //! (a||\alpha_i)*Y^{\beta_i}
        fmt::print("cipher {}\n",cipher);
        datas.emplace_back(cipher);
    }


    log("#Step3");
    std::vector<std::string> keys;
    for(auto& [key, _] : net.sessions()) { keys.push_back(key); }
    sort(keys);

    std::random_device rd;
    std::uniform_int_distribution<int> rand_gen(0, keys.size()-1);

    std::priority_queue<std::string> J;
    for(int i = 0; i < datas.size()-1; ++i) { J.push(keys[rand_gen(rd)]); }
    log("J[]:{}"_format(J.size()));

    log("send random node");
    std::map<std::string, send_one<cipher>> send_map;
    for(auto& [key, session] : net.sessions()) { send_map.emplace(key, send_one<cipher>{}); }
    for(int i = 1; i < datas.size(); ++i) {
        auto& proto = send_map[keys[rand_gen(rd)]];
        if(!proto.value) { proto.value = std::vector<cipher>{}; }
        proto.value->push_back(datas[i]);
    }

    fmt::print("send_map: {}\n",send_map);

    for (auto &key : keys) { net.send_to(encode(send_map[key]), key); } // brodcast
    log("receive random node");
    std::vector<cipher> shuffle_set;
    shuffle_set.push_back(datas[0]);
    for(auto& [port, check] : net.receive_all_with_port()) {
        if(auto proto = decode<send_one<cipher>>(wait_get(check)); proto.value) {
            shuffle_set.insert(shuffle_set.end(), proto.value->begin(), proto.value->end());
        }
    }
    fmt::print("uvs: {}\n",shuffle_set);

    log("[{}]:l={}"_format(net.port(), shuffle_set.size()));
    log("suffle");
    std::sort(shuffle_set.begin(), shuffle_set.end());

    log("#Step3.4");
    auto gamma = eig::random_r(q);              //! \gamma_i
    fmt::print("gamma: {}\n",gamma.to_dec());
    for(auto& [u ,v] : shuffle_set) {
        u = u.mul(g.exp(gamma, p), p);          //! u*g^{\gamma_i}
        v = v.mul(Y.exp(gamma, p), p);          //! v*Y^{\gamma_i}
        //fmt::print("u:{},v:{}\n", u.to_dec(), v.to_dec());
    }

    log("#Step5");
    for(int i = 0; i <= net.size(); ++i) {
        fmt::print("{}->[{}]\n", shuffle_set.size(),net.next());
        //for(auto& [u ,v] : shuffle_set) { fmt::print("u:{},v:{}\n", u.to_dec(), v.to_dec()); }
        net.send_to(encode(shuffle_set), net.next());
        auto future = net.receive_from(net.prev());
        shuffle_set = decode<std::vector<cipher>>(wait_get(future));
        fmt::print("{}<-[{}]\n", shuffle_set.size(), net.prev());
        for(auto& [u ,v] : shuffle_set) {
            //fmt::print("u:{},v:{} -> ", u.to_dec(), v.to_dec());
            v = v.mul(u.inv(p).exp(xi,p), p);
            //fmt::print("u:{},v:{}\n", u.to_dec(), v.to_dec());
        }
    }

    net.send_all(encode(shuffle_set));
    for(auto& f : net.receive_all()) {
        auto buf = decode<decltype(shuffle_set)>(wait_get(f));
        shuffle_set.insert(shuffle_set.end(), buf.begin(), buf.end());
    }

    int find=0;
    for(auto& a_alpha : a_alpha_n) {
        print_bytes("original a_alpha", Bn(a_alpha).to_bytes());
        auto bn = Bn(a_alpha);
        for(auto& [_u ,shf] : shuffle_set) {
            //auto [ai, alpha] = split_bytes(shf.to_bytes(), msg_len_bytes);
            print_bytes("shf_a_aplha",shf.to_bytes());
            //print_bytes("splitted a_i", ai);
            //print_bytes("splitted alpha",alpha);
            if(shf == bn) { fmt::print("find\n"); find++; }
            fmt::print("----\n");
        }
    }

    log(fmt::format("Result: {}\n",find));
    
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
