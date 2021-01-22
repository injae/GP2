#pragma once

#ifndef  __NETWORK_RINGNET_HPP__
#define  __NETWORK_RINGNET_HPP__

#include <simnet/simnet.hpp>

namespace simnet::ring {
    class Node {
    private:
        server server_;
        client client_;
    };

}

#endif
