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

#define __profile_runtime       true
#if (true == __profile_runtime)
    #include <chrono>
    #include <fstream>
    #include <sstream>
#endif

using namespace fmt::literals;

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
//    rapidjson::Document doc;
//    doc.SetObject();
//    serde::serialize_to(data, doc);
//    StringBuffer buffer;
//    Writer<StringBuffer> writer(buffer);
//    doc.Accept(writer);
//    return buffer.GetString();
//}

std::vector<u_int8_t> expand_bytes(std::vector<u_int8_t> data, size_t length) {
    if(data.size() == length) return data;
    std::vector<uint8_t> buffer(length, 0);
    for(auto rit = data.rbegin(), brit = buffer.rbegin(); rit != data.rend(); ++rit, ++brit) {
        *brit = *rit;
    }
    return buffer;
}


void print_bytes(const std::string& tag, std::vector<uint8_t> vec) {
    fmt::print("{}: ",tag);
    for(auto& it : vec) { fmt::print("{},", it); }
    fmt::print("\n==\n");
}

template<typename T>
inline T wait_get(std::future<T>&& value) { value.wait();  return value.get(); }
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

template<typename T>
std::pair<std::vector<u_int8_t>, std::vector<u_int8_t>> split_bytes(T&& vec, size_t point) {
    std::vector<uint8_t> first = vec, second(vec.begin()+msg_len_bytes, vec.end());
    first.erase(first.begin()+point, first.end());
    return {first, second}; 
}


void work(Node& net, std::shared_ptr<spdlog::logger> logger, const std::string& message) {
    auto log = [&net, logger](const std::string& fmt) {
        using namespace std::chrono;
        #ifdef DEBUG
        fmt::print("{}\n",fmt);
        #endif
        logger->info("[{}]:{}\n",net.port(), fmt);
        logger->flush();
    };

#if (true == __profile_runtime)
    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::nanoseconds;

    std::ofstream runtime;
    std::stringstream elapsed_time;

    std::string f_name = std::string("our_")+net.port()+std::string("_runtime.txt");
    runtime.open(f_name, std::ofstream::out);
#endif

    Bn Wi(message);

    log("== network setting end ==\n");
    log(fmt::format("info: head:{}, next:{}, port:{}, prev:{}\n",net.head(), net.next(), net.port(), net.prev()));

#if (true == __profile_runtime)
    auto s_time = high_resolution_clock::now();
#endif
    eig::secret_key sk;
    eig::public_key pk;
    if(net.head() == net.port()) {
        log("#Key Generate..");
        std::string key_cache ="{}-key.json"_format(net.port());
        if(std::filesystem::exists(key_cache)) {
            pk = serde::deserialize<eig::public_key>(serde::parse_file<nlohmann::json>(key_cache));
        } else {
            pk = eig::public_key(p_len);
            std::ofstream fs(key_cache);
            fs << serde::serialize<nlohmann::json>(pk).dump();
            fs.close();
        }
        log("#Step 1 key sharing");
        net.send_all(encode(pk));
    } else {
        pk = decode<eig::public_key>(wait_get(net.receive_from(net.head())));
    }

    auto& [p, q, g, Y, yi] = pk;

    auto xi = eig::random_r(q);     //! 1 < xi < q - 1
    sk = eig::secret_key(pk, xi);
    Y = yi = g.exp(xi, p);

    log("broadcast yi");
    net.send_all(encode(yi));

    log("Y <- yi * yi-1 ... y0");
    for(auto& yn_i : net.receive_all()) {
        auto yn = decode<Bn>(wait_get(yn_i));
        Y = Y.mul(yn, p);
    }
#if (true == __profile_runtime)
    auto e_time = high_resolution_clock::now();
    auto r_time = std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
    elapsed_time << "KG: " << r_time.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();

    s_time = high_resolution_clock::now();
#endif

    log("#Step 2");
    assert(Wi.bit_size() <= msg_len);   //! |Wi| <= 1024 - 160 = 864

    auto n = net.size()+1;
    //auto l = static_cast<size_t>(n); if(l < 3) l = 3;
    auto l = static_cast<size_t>(std::log(n)); if(l < 3) l = 3;
    //auto l = 3;
    log("l = {} = log{}"_format(l, n));

    log("Gen A");
    auto wi = expand_bytes(Wi.to_bytes(), msg_len_bytes);
    assert(Wi == Bn(wi));

    auto alpha_size = l;
    auto range = wi.size() / alpha_size;
    auto remain = wi.size() % alpha_size; 

    std::vector<std::vector<uint8_t>> a_alpha_n;
    auto alphai_arr = sha1::hash(eig::random_r(q).to_hex());    //! alpha_i
    std::vector<uint8_t> alphai{std::begin(alphai_arr), std::end(alphai_arr)};

    for(int i = 0; i < alpha_size; ++i) {
        std::vector<uint8_t> buf(wi.size(), 0);
        for(int j = 0; j < range; ++j) { auto idx = i*range+j;  buf[idx] = wi[idx]; }
        if(i+1 == alpha_size) {
            for (int j = 0; j < remain; ++j) {
                auto idx = (i+1)*range+j; buf[idx] = wi[idx];
            }
        }
        a_alpha_n.push_back(append_bytes(buf, alphai)); // <== a_alpha = (ai||alpha)
    }

    std::vector<cipher> datas;
    for(auto& a_alpha : a_alpha_n) {
        Bn si, ti, bi = eig::random_r(q);
        cipher cipher;
        cipher.s = g.exp(bi, p);                        //! g^{\beta_i}
        cipher.t = Bn(a_alpha).mul(Y.exp(bi, p),p);     //! (a||\alpha_i)*Y^{\beta_i}
        datas.emplace_back(cipher);
    }
#if (true == __profile_runtime)
    e_time = high_resolution_clock::now();
    r_time = std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
    elapsed_time << "Step#1(ctime): " << r_time.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();

    s_time = high_resolution_clock::now();
#endif

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

    for (auto &key : keys) { net.send_to(encode(send_map[key]), key); } // broadcast
    log("receive random node");
    std::vector<cipher> shuffle_set;
    shuffle_set.push_back(datas[0]);
    for(auto& [port, check] : net.receive_all_with_port()) {
        if(auto proto = decode<send_one<cipher>>(wait_get(check)); proto.value) {
            shuffle_set.insert(shuffle_set.end(), proto.value->begin(), proto.value->end());
        }
    }
#if (true == __profile_runtime)
    e_time = high_resolution_clock::now();
    r_time = std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
    elapsed_time << "Step#1(ntime): " << r_time.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();

    s_time = high_resolution_clock::now();
#endif    

    log("[{}]:l={}"_format(net.port(), shuffle_set.size()));
    log("suffle");
    std::sort(shuffle_set.begin(), shuffle_set.end());

    log("#Step3.4");
    auto gamma = eig::random_r(q);              //! \gamma_i
    for(auto& [u ,v] : shuffle_set) {
        u = u.mul(g.exp(gamma, p), p);          //! u*g^{\gamma_i}
        v = v.mul(Y.exp(gamma, p), p);          //! v*Y^{\gamma_i}
    }
#if (true == __profile_runtime)
    e_time = high_resolution_clock::now();
    r_time = std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
    elapsed_time << "Step#2(ctime): " << r_time.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();

    auto c_rtime = std::chrono::high_resolution_clock::duration::zero(),
         n_rtime = std::chrono::high_resolution_clock::duration::zero();
#endif    

    log("#Step5");
    for(int i = 0; i <= net.size(); ++i) {
#if (true == __profile_runtime)
        s_time = high_resolution_clock::now();
#endif
        //log(fmt::format("{}->[{}]\n", shuffle_set.size(),net.next()));
        net.send_to(encode(shuffle_set), net.next());
        auto future = net.receive_from(net.prev());
        shuffle_set = decode<std::vector<cipher>>(wait_get(future));
        //log(fmt::format("{}<-[{}]\n", shuffle_set.size(), net.prev()));
#if (true == __profile_runtime)
        e_time = high_resolution_clock::now();
        n_rtime += std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
    
        s_time = high_resolution_clock::now();
#endif
        for(auto& [u ,v] : shuffle_set) {
            v = v.mul(u.inv(p).exp(xi,p), p);
        }
#if (true == __profile_runtime)
        e_time = high_resolution_clock::now();
        c_rtime += std::chrono::duration_cast<std::chrono::nanoseconds>(e_time - s_time);
#endif
    }
#if (true == __profile_runtime)
    elapsed_time << "Step#3(ctime): " << c_rtime.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();
    elapsed_time << "Step#3(ntime): " << n_rtime.count() * 1e-6 << " msec\n";
    runtime << elapsed_time.str();
#endif

    net.send_all(encode(shuffle_set));
    for(auto& f : net.receive_all()) {
        auto buf = decode<decltype(shuffle_set)>(wait_get(f));
        shuffle_set.insert(shuffle_set.end(), buf.begin(), buf.end());
    }

    std::vector<std::vector<uint8_t>> ai_s;
    Bn alphai_bn{alphai};
    for(auto& [_u ,shf] : shuffle_set) {
        auto [ai, alpha] = split_bytes(expand_bytes(shf.to_bytes(), p_len/8), msg_len_bytes);
        if(alphai_bn == Bn(alpha)) { ai_s.push_back(ai); }
    }

    std::vector<uint8_t> al(msg_len_bytes, 0);
    for(auto& ai : ai_s) {
        std::transform(al.begin(), al.end(), ai.begin(), al.begin(), std::bit_xor<uint8_t>());
    }
    log(fmt::format("message: {}\n", Bn(al).to_string()));

#if (true == __profile_runtime)
    runtime.close();
#endif
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
        auto logger = spdlog::basic_logger_mt("node-{}"_format(net.port()), "net2-logs/{}-log.txt"_format(net.port()));
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
    }
    
    return 0;
}
